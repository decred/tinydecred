"""
Copyright (c) 2020, the Decred developers
See LICENSE for details

Tests use the "http_get_post" fixture in conftest.py .
"""

import json
from pathlib import Path

import pytest

from decred import DecredError
from decred.crypto import opcode
from decred.dcr import account, agenda, txscript
from decred.dcr.dcrdata import (
    DcrdataBlockchain,
    DcrdataClient,
    DcrdataError,
    DcrdataPath,
    checkOutput,
    makeOutputs,
)
from decred.dcr.nets import testnet
from decred.dcr.wire import msgtx
from decred.util.encode import ByteArray


BASE_URL = "https://example.org/"


AGENDA_CHOICES_RAW = dict(
    id="choices_id",
    description="description",
    bits=0,
    isabstain=False,
    isno=False,
    count=0,
    progress=0.0,
)

AGENDA_RAW = dict(
    id="agenda_id",
    description="description",
    mask=0,
    starttime=0,
    expiretime=0,
    status="status",
    quorumprogress=0.0,
    choices=[AGENDA_CHOICES_RAW],
)

AGENDAS_INFO_RAW = {
    "currentheight": 0,
    "startheight": 0,
    "endheight": 0,
    "hash": "hash",
    "voteversion": 0,
    "quorum": 0.0,
    "totalvotes": 0,
    "agendas": [AGENDA_RAW],
}


def test_dcrdatapath(http_get_post):
    ddp = DcrdataPath()

    # __getattr__
    with pytest.raises(DcrdataError):
        ddp.no_such_path()

    # Empty URI, needed for post.
    with pytest.raises(DcrdataError):
        ddp.getCallsignPath()
    ddp.addCallsign([], "")
    csp = ddp.getCallsignPath()
    assert csp == ""

    # Non-empty URI.
    with pytest.raises(DcrdataError):
        ddp.getCallsignPath("address")
    ddp.addCallsign(["address"], "/%s")
    csp = ddp.getCallsignPath("address", address="1234")
    assert csp == "/address?address=1234"

    # Post. Queue the response we want first.
    http_get_post(("", "'data'"), {})
    ret = ddp.post("data")
    assert ret == {}


def test_makeoutputs():
    # Amount is non-integer.
    with pytest.raises(DecredError):
        makeOutputs([("", None)], None)

    # Amount is negative.
    with pytest.raises(DecredError):
        makeOutputs([("", -1)], None)

    address = "TsfDLrRkk9ciUuwfp2b8PawwnukYD7yAjGd"  # testnet return address
    value = int(1 * 1e8)  # 1 DCR, atoms
    output = makeOutputs([(address, value)], testnet)[0]
    assert isinstance(output, msgtx.TxOut)
    assert output.value == value


def test_checkoutput():
    # Amount is zero.
    tx = msgtx.TxOut()
    with pytest.raises(DecredError):
        checkOutput(tx, 0)

    # Amount is negative.
    tx = msgtx.TxOut(-1)
    with pytest.raises(DecredError):
        checkOutput(tx, 0)

    # Amount is too large.
    tx = msgtx.TxOut(txscript.MaxAmount + 1)
    with pytest.raises(DecredError):
        checkOutput(tx, 0)

    # Tx is dust output.
    script = ByteArray([opcode.OP_RETURN, opcode.OP_NOP])
    tx = msgtx.TxOut(value=1, pkScript=script)
    with pytest.raises(DecredError):
        checkOutput(tx, 0)


class MockWebsocketClient:
    def __init__(self):
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)

    def close(self):
        pass


def preload_api_list(http_get_post):
    # Load the list of API calls.
    data_file = Path(__file__).resolve().parent / "test-data" / "dcrdata.json"
    with open(data_file) as f:
        api_list = json.loads(f.read())

    # Queue the list of API calls.
    http_get_post(f"{BASE_URL}api/list", api_list)


class TestDcrdataClient:
    def test_misc(self, http_get_post, capsys):
        preload_api_list(http_get_post)
        ddc = DcrdataClient(BASE_URL)

        assert len(ddc.listEntries) == 84
        assert len(ddc.subscribedAddresses) == 0
        assert ddc.endpointList()[0] == ddc.listEntries[0][1]

        # This prints to stdout.
        ddc.endpointGuide()
        out, err = capsys.readouterr()
        assert len(out.splitlines()) == 84

    def test_subscriptions(self, http_get_post):
        preload_api_list(http_get_post)
        ddc = DcrdataClient(BASE_URL)

        # Set the mock WebsocketClient.
        ddc.ps = MockWebsocketClient()

        ddc.subscribedAddresses = ["already_there"]
        ddc.subscribeAddresses(["already_there", "new_one"])
        assert ddc.ps.sent[0]["message"]["message"] == "address:new_one"

        ddc.ps.sent = []
        ddc.subscribeBlocks()
        assert ddc.ps.sent[0]["message"]["message"] == "newblock"

    def test_static(self):
        assert DcrdataClient.timeStringToUnix("1970-01-01 00:00:00") == 0
        assert DcrdataClient.RFC3339toUnix("1970-01-01T00:00:00Z") == 0


class TestDcrdataBlockchain:
    # Test data from block #427282.
    utxos = (
        # Coinbase.
        dict(
            address="DsnxqhJX2tjyjbfb9y4yPdpJ744G9fLhbbF",
            txid="ba0ce58eaa1b1402b8f33d84034014712add4d2955d1dd01adea2612e9dc6b8a",
            vout=2,
            ts=1582827409,
            scriptPubKey="76a914f14f995d7b8c37c961bdb1baf431a18026f7e31088ac",
            height=427338,
            amount=7.5534513,
            satoshis=755345130,
            confirmations=3,
        ),
        # Ticket.
        dict(
            address="Dcuq3UdEQ3SHy3W6wfmbsSZctQjKSn8o8HV",
            txid="40039b114c2a497ebd324d9d6c34a20b32caedfb036fbcb5523471adbafa32a1",
            vout=0,
            ts=1582825041,
            scriptPubKey="baa914f5618dfc002becfe840da65f6a49457f41d4f21787",
            height=427325,
            amount=147.73014984,
            satoshis=14773014984,
            confirmations=5,
        ),
        # Standard.
        dict(
            address="DshiCywHki7LeKK4G97ifphLR5hiicAhiKE",
            txid="fe332b35fa0a8a8aa2d247a35f45553935e0b96d33e1a8158a1a863307d5bdf3",
            vout=1,
            ts=1582817341,
            scriptPubKey="76a914b7b28003b805aaba589092e28f30e436f0cd05df88ac",
            height=427282,
            amount=80.81940674,
            satoshis=8081940674,
            confirmations=3,
        ),
    )
    # fmt: off
    txs = (
        ("ba0ce58eaa1b1402b8f33d84034014712add4d2955d1dd01adea2612e9dc6b8a", (
            "0100000001000000000000000000000000000000000000000000000000000000000000000"
            "0ffffffff00ffffffff03e8997c0700000000000017a914f5916158e3e2c4551c1796708d"
            "b8367207ed13bb87000000000000000000000e6a0c4a850600589b9dfdecb7e667eaa6052"
            "d0000000000001976a914f14f995d7b8c37c961bdb1baf431a18026f7e31088ac00000000"
            "00000000015a3568340000000000000000ffffffff0800002f646372642f"
        )),
        ("40039b114c2a497ebd324d9d6c34a20b32caedfb036fbcb5523471adbafa32a1", (
            "01000000024f23123ce6a665cc092d2947a56ff6a88dcde4c74f72adff76d976b188611df"
            "b0000000000ffffffff4f23123ce6a665cc092d2947a56ff6a88dcde4c74f72adff76d976"
            "b188611dfb0100000000ffffffff05c8518a7003000000000018baa914f5618dfc002becf"
            "e840da65f6a49457f41d4f2178700000000000000000000206a1ebee010b0d6369633d6fb"
            "12d67559440e2146c8dbf7330b00000000000058000000000000000000001abd76a914000"
            "000000000000000000000000000000000000088ac00000000000000000000206a1e9ce9c4"
            "6b4e99d014ff8fcbc76fa374258d6b2f2afd327f700300000000580000000000000000000"
            "01abd76a914000000000000000000000000000000000000000088ac000000008085060002"
            "f7330b00000000003c8506000a0000006a47304402205cc30a0c1e4d22e7ac3473b80f778"
            "9d694f17e18a39defe156814418edeeb34302207ec4eb9ae7eba710608e49b363129147c8"
            "4319f8cf065733522a2ac16a66fd260121021f2675b5f8403d9095c1874efde16719684d0"
            "490cc8836cbe5dadc3be4650dbbfd327f70030000003c8506000a0000006b483045022100"
            "dce25b12cf5fb6d97123f7ed128df45452296c5f6b80736d34c23f71600445dc022062917"
            "c128406c371983eceaeb9fa47e417f1d6b84da1f7faa888a2cda6cee8ad0121021f2675b5"
            "f8403d9095c1874efde16719684d0490cc8836cbe5dadc3be4650dbb"
        )),
        ("fe332b35fa0a8a8aa2d247a35f45553935e0b96d33e1a8158a1a863307d5bdf3", (
            "01000000022b7417082c038ad30555f69723516b0372b2afbe7d888e3a52995a759c9b26b"
            "e0200000001ffffffff81f6d14d0cc35a385af056bd3c3dd95e951fc9007ba9aaa76c3f31"
            "7e7c7b969d0100000000ffffffff026c5d8a700300000000001976a914ead3999b4c08c93"
            "248e54a6dea44f3a3e4e58fb088acc2a0b8e10100000000001976a914b7b28003b805aaba"
            "589092e28f30e436f0cd05df88ac0000000000000000020e7367e20200000011840600020"
            "000006a47304402207fcf2f4522fc243348f0691df3c6ec0e01eb3f160d97ed1d0b2b2eb7"
            "21bba3ac0220799deaf6aa5053089a1ffae35298e67156c455f18a2862e6cdb54ec81c32f"
            "d1d01210399a38b70c02626ffb64451b1b5d8b95fd9f8cb02aaaf062cd8e5a023a5a2fa37"
            "7e9bdb6f02000000ec840600040000006a47304402200d5b9d3eb925d6f028640d810f152"
            "a19ea462bf15a71eba2b5a6080c8b02e161022022d492ce6fc296d9cbc61122838add71e9"
            "a01bbb7c53659d0ee8f7927b26eef6012103c8656c7d5002fdead42f844a6ea370c34d581"
            "0bed487af9827a27a820b31a880"
        )),
    )
    # fmt: on

    def test_misc(self, http_get_post, tmp_path):
        preload_api_list(http_get_post)
        http_get_post(f"{BASE_URL}api/block/best", dict(height=1))
        ddb = DcrdataBlockchain(str(tmp_path / "test.db"), testnet, BASE_URL)
        assert ddb.tipHeight == 1

        # getAgendasInfo
        http_get_post(f"{BASE_URL}api/stake/vote/info", AGENDAS_INFO_RAW)
        agsinfo = ddb.getAgendasInfo()
        assert isinstance(agsinfo, agenda.AgendasInfo)

    def test_subscriptions(self, http_get_post, tmp_path):
        # Exception in updateTip.
        preload_api_list(http_get_post)
        with pytest.raises(DecredError):
            DcrdataBlockchain(str(tmp_path / "test.db"), testnet, BASE_URL)

        # Successful creation.
        preload_api_list(http_get_post)
        http_get_post(f"{BASE_URL}api/block/best", dict(height=1))
        ddb = DcrdataBlockchain(str(tmp_path / "test.db"), testnet, BASE_URL)

        # Set the mock WebsocketClient.
        ddb.dcrdata.ps = MockWebsocketClient()

        # Receiver
        block_queue = []

        def blockReceiver(sig):
            block_queue.append(sig)

        # Receiver
        addr_queue = []

        def addrReceiver(addr, txid):
            addr_queue.append((addr, txid))

        # subscribeBlocks
        ddb.subscribeBlocks(blockReceiver)
        assert ddb.dcrdata.ps.sent[0]["message"]["message"] == "newblock"
        ddb.dcrdata.ps.sent = []

        # subscribeAddresses
        with pytest.raises(DecredError):
            ddb.subscribeAddresses([])
        ddb.subscribeAddresses(["new_one"], addrReceiver)
        assert ddb.dcrdata.ps.sent[0]["message"]["message"] == "address:new_one"

        # pubsubSignal
        assert ddb.pubsubSignal("done") is None
        assert ddb.pubsubSignal(dict(event="subscribeResp")) is None
        assert ddb.pubsubSignal(dict(event="ping")) is None
        assert ddb.pubsubSignal(dict(event="unknown")) is None
        # pubsubSignal address
        sig = dict(
            event="address",
            message=dict(address="the_address", transaction="transaction"),
        )
        ddb.pubsubSignal(sig)
        assert addr_queue[0] == ("the_address", "transaction")
        # pubsubSignal newblock
        sig = dict(event="newblock", message=dict(block=dict(height=1)))
        ddb.pubsubSignal(sig)
        assert block_queue[0] == sig

    def test_utxos(self, http_get_post, tmp_path):
        preload_api_list(http_get_post)
        http_get_post(f"{BASE_URL}api/block/best", dict(height=1))
        ddb = DcrdataBlockchain(str(tmp_path / "test.db"), testnet, BASE_URL)

        # txVout error
        with pytest.raises(DecredError):
            ddb.txVout(self.txs[2][0], 0).satoshis

        # processNewUTXO
        # Preload tx and tinfo.
        txURL = f"{BASE_URL}api/tx/hex/{self.txs[1][0]}"
        http_get_post(txURL, self.txs[1][1])
        tinfoURL = f"{BASE_URL}api/tx/{self.utxos[1]['txid']}/tinfo"
        tinfo = dict(
            status="live",
            purchase_block=dict(
                hash="0000000000000000270916ab2705a3a2053f32344e195e87f787ffe0f977a528",
                height=427325,
            ),
            maturity_height=427581,
            expiration_height=468541,
            lottery_block=None,
            vote=None,
            revocation=None,
        )
        http_get_post(tinfoURL, tinfo)
        utxo = ddb.processNewUTXO(self.utxos[1])
        assert utxo.tinfo.purchaseBlock.hash == reversed(
            ByteArray(tinfo["purchase_block"]["hash"])
        )

        # UTXOs
        assert len(ddb.UTXOs([])) == 0

        # Precompute the UTXO data.
        addrs = [utxo["address"] for utxo in self.utxos]
        addrStr = ",".join(addrs)
        utxoURL = f"{BASE_URL}insight/api/addr/{addrStr}/utxo"

        # Preload the UTXOs but not the txs.
        http_get_post(utxoURL, self.utxos)
        with pytest.raises(DecredError):
            ddb.UTXOs(addrs)

        # Preload both the UTXOs and the txs.
        http_get_post(utxoURL, self.utxos)
        for txid, tx in self.txs:
            txURL = f"{BASE_URL}api/tx/hex/{txid}"
            http_get_post(txURL, tx)
        assert len(ddb.UTXOs(addrs)) == 3

        # txsForAddr
        txsURL = f"{BASE_URL}insight/api/addr/the_address/txs"
        # No transactions for an address.
        http_get_post(txsURL, {})
        assert ddb.txsForAddr("the_address") == []
        # Some transactions for an address.
        http_get_post(txsURL, {"transactions": "txs"})
        assert ddb.txsForAddr("the_address") == "txs"

        # txVout success
        assert ddb.txVout(self.txs[2][0], 0).satoshis == 14773017964

        # approveUTXO
        utxo = account.UTXO.parse(self.utxos[1])
        utxo.maturity = 2
        assert ddb.approveUTXO(utxo) is False
        utxo.maturity = None
        assert ddb.approveUTXO(utxo) is False
        utxo = account.UTXO.parse(self.utxos[0])
        assert ddb.approveUTXO(utxo) is True

        # confirmUTXO
        # No confirmation.
        utxo = account.UTXO.parse(self.utxos[2])
        assert ddb.confirmUTXO(utxo) is False
        # Confirmation.
        blockHash = "00000000000000002b197e4018b990efb85e6bd43ffb15f7ede97a78f806a3f8"
        txURL = f"{BASE_URL}api/tx/{self.txs[2][0]}"
        decodedTx = {"block": {"blockhash": blockHash}}
        http_get_post(txURL, decodedTx)
        headerURL = f"{BASE_URL}api/block/hash/{blockHash}/header/raw"
        blockHeader = {
            "hex": (
                "07000000e00b3a83dc60f961d8f516ece63e6d009eff4c2af50139150000"
                "000000000000873684038a5d384cf123ee39d39bdf9f65cf4051ec4d420f"
                "e909c16344329aaa35879931c8695d9be6f9259fa7467c51d0c7e601d95c"
                "c78fdd458210503865af0100721e0a6d2bf90500040091a40000e62f3418"
                "c8518a700300000012850600213300003de0575e6e8b9d13e691326a1fd4"
                "3a0000000000000000000000000000000000000000000000000007000000"
            ),
        }
        http_get_post(headerURL, blockHeader)
        assert ddb.confirmUTXO(utxo) is True

    def test_blocks(self, http_get_post, tmp_path):
        preload_api_list(http_get_post)
        http_get_post(f"{BASE_URL}api/block/best", dict(height=1))
        ddb = DcrdataBlockchain(str(tmp_path / "test.db"), testnet, BASE_URL)

        # blockHeader
        blockHash = "00000000000000002b197e4018b990efb85e6bd43ffb15f7ede97a78f806a3f8"
        with pytest.raises(DecredError):
            ddb.blockHeader(blockHash)

        # blockHeaderByHeight
        blockHeight = 427282
        with pytest.raises(DecredError):
            ddb.blockHeaderByHeight(blockHeight).id()
        # Preload the block header.
        headerURL = f"{BASE_URL}api/block/{blockHeight}/header/raw"
        blockHeader = {
            "hex": (
                "07000000e00b3a83dc60f961d8f516ece63e6d009eff4c2af50139150000"
                "000000000000873684038a5d384cf123ee39d39bdf9f65cf4051ec4d420f"
                "e909c16344329aaa35879931c8695d9be6f9259fa7467c51d0c7e601d95c"
                "c78fdd458210503865af0100721e0a6d2bf90500040091a40000e62f3418"
                "c8518a700300000012850600213300003de0575e6e8b9d13e691326a1fd4"
                "3a0000000000000000000000000000000000000000000000000007000000"
            ),
        }
        http_get_post(headerURL, blockHeader)
        assert ddb.blockHeaderByHeight(blockHeight).id() == blockHash
        # Exercise the database code.
        assert ddb.blockHeaderByHeight(blockHeight).id() == blockHash

        # blockForTx
        # Preload the first broken decoded tx.
        txURL = f"{BASE_URL}api/tx/{self.txs[2][0]}"
        decodedTx = {"block": {}}
        http_get_post(txURL, decodedTx)
        assert ddb.blockForTx(self.txs[2][0]) is None
        # Preload the second broken decoded tx.
        txURL = f"{BASE_URL}api/tx/{self.txs[2][0]}"
        decodedTx = {"block": {"blockhash": ""}}
        http_get_post(txURL, decodedTx)
        assert ddb.blockForTx(self.txs[2][0]) is None
        # Preload the right decoded tx.
        txURL = f"{BASE_URL}api/tx/{self.txs[2][0]}"
        decodedTx = {"block": {"blockhash": blockHash}}
        http_get_post(txURL, decodedTx)
        assert ddb.blockForTx(self.txs[2][0]).height == blockHeight
        # Preload the block header.
        headerURL = f"{BASE_URL}api/block/hash/{blockHash}/header/raw"
        http_get_post(headerURL, blockHeader)
        assert ddb.blockForTx(self.txs[2][0]).height == blockHeight
        # Exercise the database code.
        assert ddb.blockForTx(self.txs[2][0]).height == blockHeight
