"""
Copyright (c) 2020, the Decred developers
See LICENSE for details

Tests use the "http_get_post" fixture in conftest.py .
"""

import pytest

from decred.crypto import crypto
from decred.dcr import rpc
from decred.dcr.blockchain import LocalNode
from decred.dcr.nets import mainnet
from decred.util.encode import ByteArray


@pytest.fixture
def node(monkeypatch, tmp_path):
    existsAddresses = set()

    class TestWsClient:
        def __init__(self, url, user, pw, cert=None):
            pass

        def existsAddresses(self, addrs):
            return [addr in existsAddresses for addr in addrs]

    monkeypatch.setattr(rpc, "WebsocketClient", TestWsClient)
    bc = LocalNode(
        netParams=mainnet,
        dbPath=tmp_path / "tmp.db",
        url="url",
        user="user",
        pw="pass",
    )
    bc._existsAddresses = existsAddresses
    return bc


def newExtendedKey():
    xk = crypto.ExtendedKey.new(
        ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b
    )
    return xk.deriveCoinTypeKey(mainnet)


# A sampling of addresses derived from the newExtendedKey key.
testAddrs = {
    3: "DsapZcX3rBfrx85nbWLVoL5PpQAFUJW8ygV",
    4: "Dscb7StES7pLCgWUVA6jBVpPMdHyKjqSVc4",
    9: "DsTTd9nYHsE6ygQSYkeCF3Lt9x3gfnzJNNh",
}


def test_discoverAddresses(node):
    existAddrs = node._existsAddresses

    dcrKey = newExtendedKey()

    # Calling with index 0 and no addresses should return an empty result set.
    discovered = node.discoverAddresses(dcrKey, 0, 5)
    assert len(discovered) == 0

    # Stick an address at indexes 3 and 4
    existAddrs.add(testAddrs[3])
    existAddrs.add(testAddrs[4])
    discovered = node.discoverAddresses(dcrKey, 0, 5)
    assert len(discovered) == 2
    assert discovered[0] == 3
    assert discovered[1] == 4

    # Now stick one at 4 + gap = 9
    existAddrs.add(testAddrs[9])
    discovered = node.discoverAddresses(dcrKey, 0, 5)
    assert len(discovered) == 3
    assert discovered[2] == 9

    # But sticking in just the one at 9 should return nothing still
    existAddrs.clear()
    existAddrs.add(testAddrs[9])
    discovered = node.discoverAddresses(dcrKey, 0, 5)
    assert len(discovered) == 0
