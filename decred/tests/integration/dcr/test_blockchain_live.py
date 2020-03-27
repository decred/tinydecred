"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred.dcr.blockchain import LocalNode
from decred.dcr.nets import mainnet
from decred.dcr.wire.msgtx import OutPoint
from decred.util.encode import ByteArray, rba


@pytest.fixture
def node(dcrdConfig, tmp_path):
    if dcrdConfig is None:
        return "no configuration found"
    try:
        bc = LocalNode(
            netParams=mainnet,
            dbPath=tmp_path / "tmp.db",
            url="https://" + dcrdConfig["rpclisten"],
            user=dcrdConfig["rpcuser"],
            pw=dcrdConfig["rpcpass"],
            certPath=dcrdConfig["rpccert"],
        )
    except Exception as e:
        return e
    yield bc
    bc.close()


def test_syncAccount(node):
    # sync a small range of headers.
    node.syncHeaderRange(400000, 400100)

    # An address from block 400,051, a split transaction to fund a ticket in
    # block 400,053
    addr51_0out = "DsSMy2pPZmS7Jd9QoGbzX2DfhAJDqwftWTR"
    # An address from a previous outpoint being spent in block 400,074. Also
    # has an output in block 400,053.
    addr74_0in = "DsbZZXdkA4JKBUK6YbqGmDkgDryKBVdGVD5"
    # A ticket being spent in transaction 400,025
    ticket = OutPoint(
        txHash=rba("60d97229b6229923d6c4c3c6f290fbc507833186f3d1eed1e603e205e0dfe493"),
        idx=0,
        tree=1,
    )

    startHash = node.mainchainDB.first()[1]
    print("startHash", startHash.rhex())

    scanBlocks = node.syncAccount(
        addrs=[addr51_0out, addr74_0in], outPoints=[ticket], startHash=startHash,
    )

    # A mapping of block hashes to number of transactions expected.
    expTxs = {
        rba("00000000000000000f9aed681de1bb5ee8d0022ec427d2df526534eab4675c59"): 1,
        rba("000000000000000015749883c3cf975ea3565695a833e6f44a5caabf8e132ff3"): 1,
        rba("000000000000000002e6de7314fe8062e1f8abf0711b8cf1f026aff0876466b6"): 2,
        rba("0000000000000000097661b13a8d4d8d99753445b21f91ab53f66bdbc088338c"): 1,
    }

    assert len(scanBlocks) == len(expTxs)
    for block in scanBlocks:
        assert block.hash in expTxs
        assert expTxs[block.hash] == len(block.txs)


def test_syncHeaders(node):
    # Get the current best tip.
    tip = node.rpc.getBestBlock()
    # Go back 10 block, inclusive of ends, so 11 blocks total to sync.
    rootHash = node.rpc.getBlockHash(tip.height - 10)
    rootHeight = node.rpc.getBlock(rootHash).height

    synced, orphans = node.syncHeaders(rootHash)
    firstHeight, firstHash = node.mainchainDB.first()
    assert firstHeight == rootHeight
    assert firstHash == rootHash
    assert len(node.headerDB) >= 11
    assert len(node.mainchainDB) >= 11
    assert synced >= 11
    assert len(orphans) == 0
    for height, blockHash in node.mainchainDB.items():
        assert node.rpc.getBlock(blockHash).height == height

    # Insert a wrong hash at the tip height
    node.mainchainDB[tip.height] = ByteArray(length=32)

    # Start with an earlier root
    newRootHash = node.rpc.getBlockHash(rootHeight - 2)

    preSyncHeight = node.mainchainDB.last()[0]
    synced, orphans = node.syncHeaders(newRootHash)
    # Expect 3 to be synced. 2 from the beginning, 1 from the reorg.
    assert synced == node.mainchainDB.last()[0] - preSyncHeight + 3
    assert len(orphans) == 1

    # Clear the database and test syncing from genesis and more than
    # maxBlocksPerRescan, just to exercise the paths.
    node.mainchainDB.clear()
    node.syncHeaderRange(0, 3000)
    assert len(node.mainchainDB) == 3000
