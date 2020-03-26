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
from decred.dcr import account, agenda, dcrdata, nets, txscript
from decred.dcr.dcrdata import (
    DcrdataBlockchain,
    DcrdataClient,
    DcrdataError,
    DcrdataPath,
)
from decred.dcr.nets import testnet
from decred.dcr.wire import msgtx
from decred.util import ws
from decred.util.encode import ByteArray


BASE_URL = "https://example.org/"
API_URL = BASE_URL + "api"
INSIGHT_URL = BASE_URL + "insight/api"

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

    # Empty URL, needed for post.
    with pytest.raises(DcrdataError):
        ddp.getCallsignPath()
    ddp.addCallsign([], "")
    csp = ddp.getCallsignPath()
    assert csp == ""

    # Non-empty URL.
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
        dcrdata.makeOutputs([("", None)], None)

    # Amount is negative.
    with pytest.raises(DecredError):
        dcrdata.makeOutputs([("", -1)], None)

    address = "TsfDLrRkk9ciUuwfp2b8PawwnukYD7yAjGd"  # testnet return address
    value = int(1 * 1e8)  # 1 DCR, atoms
    output = dcrdata.makeOutputs([(address, value)], testnet)[0]
    assert isinstance(output, msgtx.TxOut)
    assert output.value == value


def test_checkoutput():
    # Amount is zero.
    tx = msgtx.TxOut()
    with pytest.raises(DecredError):
        dcrdata.checkOutput(tx, 0)

    # Amount is negative.
    tx = msgtx.TxOut(-1)
    with pytest.raises(DecredError):
        dcrdata.checkOutput(tx, 0)

    # Amount is too large.
    tx = msgtx.TxOut(txscript.MaxAmount + 1)
    with pytest.raises(DecredError):
        dcrdata.checkOutput(tx, 0)

    # Tx is dust output.
    script = ByteArray([opcode.OP_RETURN, opcode.OP_NOP])
    tx = msgtx.TxOut(value=1, pkScript=script)
    with pytest.raises(DecredError):
        dcrdata.checkOutput(tx, 0)


class MockWebSocketClient:
    def __init__(self, url, on_message, on_close, on_error):
        self.on_message = on_message
        self.on_close = on_close
        self.on_error = on_error
        self.sent = []
        self.received = []

    def send(self, msg):
        self.sent.append(msg)

    def close(self):
        self.on_close(self)

    def get_emitter(self):
        def emitter(msg):
            self.received.append(msg)

        return emitter

    def empty_queues(self):
        self.sent = []
        self.received = []


class TweakedDcrdataClient(DcrdataClient):
    def __init__(self, url, emitter=None, monkeypatch=None):
        if monkeypatch is None:
            raise RuntimeError("Need monkeypatch")
        monkeypatch.setattr(ws, "Client", MockWebSocketClient)
        super().__init__(url, emitter)
        self.psClient()
        self.emitter = self.ps.get_emitter()


def preload_api_list(http_get_post, baseURL=API_URL):
    # Load the list of API calls.
    data_file = Path(__file__).resolve().parent / "test-data" / "dcrdata.json"
    with open(data_file) as f:
        api_list = json.loads(f.read())

    # Queue the list of API calls.
    http_get_post(f"{baseURL}/list", api_list)


class TestDcrdataClient:
    def test_misc(self, http_get_post, capsys):
        preload_api_list(http_get_post)
        ddc = DcrdataClient(BASE_URL)

        assert len(ddc.listEntries) == 85
        assert len(ddc.subscribedAddresses) == 0
        assert ddc.endpointList()[0] == ddc.listEntries[0][1]

        # This prints to stdout.
        ddc.endpointGuide()
        out, err = capsys.readouterr()
        assert len(out.splitlines()) == 85

    def test_subscriptions(self, http_get_post, monkeypatch):
        # Create a DcrdataClient with a mocked ws.Client that captures the
        # signals and stores the messages.
        preload_api_list(http_get_post)
        ddc = TweakedDcrdataClient(BASE_URL, None, monkeypatch)
        dcrdata._subcounter = 0

        # Test sending.

        ddc.subscribedAddresses = ["already_there"]
        ddc.subscribeAddresses(["already_there", "new_one"])
        assert ddc.ps.sent[0] == (
            '{"event": "subscribe", '
            '"message": {"request_id": 1, "message": "address:new_one"}}'
        )
        ddc.subscribeBlocks()
        assert ddc.ps.sent[1] == (
            '{"event": "subscribe", '
            '"message": {"request_id": 1, "message": "newblock"}}'
        )

        # Test receiving.

        ddc.ps.on_message(ddc.ps, '{"event": "ping"}')
        assert not ddc.ps.received

        ddc.ps.on_message(ddc.ps, "not_json")
        assert ddc.ps.received[0] == "not_json"

        ddc.ps.on_close(ddc.ps)
        assert ddc.ps.received[1] == dcrdata.WS_DONE

        ddc.ps.on_error(ddc.ps, DecredError("test_error"))

    def test_static(self):
        assert DcrdataClient.timeStringToUnix("1970-01-01 00:00:00") == 0
        assert DcrdataClient.RFC3339toUnix("1970-01-01T00:00:00Z") == 0


class TestDcrdataBlockchain:
    stakePool = dict(
        height=429340,
        size=40816,
        value=5594728.53643864,
        valavg=137.07194571831243,
        winners=[
            "73af43698b39ace0208e19d82932aeba5760a6f55525d5598de26fb71daa7cca",
            "c917e7ca06cb18d013f19a919d8e8c75deb3fdb4927a7fc0e1f0832bbf27359b",
            "11638875f8eb3118c6d76bf78f2a6757446ea7af22c99f93c7a177e34ddcf51a",
            "da8f1e54fe9df02f72c0c00f5bf30fed8d596518403ed61ccf0460361ea64b27",
            "34c99c6d3cf6db02b31fce07125a347791d675e8d9a2ca06b257939fc346f38e",
        ],
    )

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
        ("be269b9c755a99523a8e887dbeafb272036b512397f65505d38a032c0817742b", (
            "0100000002000000000000000000000000000000000000000000000000000000000000000"
            "0ffffffff00ffffffff86bfb570868726584df65bc0aed5be7aeed3f5319fa0837057c92b"
            "4a833d8dfc0000000001ffffffff0300000000000000000000266a2437ef9650679e18f27"
            "a50f7395999b799917d567f7bcab609000000000000000010840600000000000000000000"
            "00086a060100070000000e7367e20200000000001abb76a914403bb89f167da504778da66"
            "4ba6a332dce8951b088ac0000000000000000026e739d050000000000000000ffffffff02"
            "0000a0ffc9dc0200000088800600050000006b483045022100c5110b6472d1d948ff80762"
            "21b4fe39487ea11c66d8f8fa99fe16ec05ed3cae9022042114291e70cea9e293211c6404f"
            "409e254a1eb7559c86dc785088d60c53980201210399a38b70c02626ffb64451b1b5d8b95"
            "fd9f8cb02aaaf062cd8e5a023a5a2fa37"
        )),
    )
    # fmt: on
    blockHash = "00000000000000002b197e4018b990efb85e6bd43ffb15f7ede97a78f806a3f8"
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
    blockHeight = 427282
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

    def test_misc(self, http_get_post):
        preload_api_list(http_get_post)
        http_get_post(f"{API_URL}/block/best", dict(height=1))
        ddb = DcrdataBlockchain(":memory:", testnet, BASE_URL)
        assert ddb.tipHeight == 1

        # getAgendasInfo
        http_get_post(f"{API_URL}/stake/vote/info", AGENDAS_INFO_RAW)
        agsinfo = ddb.getAgendasInfo()
        assert isinstance(agsinfo, agenda.AgendasInfo)

        # ticketPoolInfo
        http_get_post(f"{API_URL}/stake/pool", self.stakePool)
        assert ddb.ticketPoolInfo().height == self.stakePool["height"]

        # nextStakeDiff
        http_get_post(f"{API_URL}/stake/diff", {"estimates": {"expected": 1}})
        assert ddb.nextStakeDiff() == 1e8

    def test_subscriptions(self, http_get_post, monkeypatch):
        # Exception in updateTip.
        preload_api_list(http_get_post)
        with pytest.raises(DecredError):
            DcrdataBlockchain(":memory:", testnet, BASE_URL)

        # Successful creation.
        preload_api_list(http_get_post)
        http_get_post(f"{API_URL}/block/best", dict(height=1))
        ddb = DcrdataBlockchain(":memory:", testnet, BASE_URL, skipConnect=True)
        ddb.dcrdata = TweakedDcrdataClient(ddb.datapath, ddb.pubsubSignal, monkeypatch)
        ddb.updateTip()
        dcrdata._subcounter = 0

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
        assert ddb.dcrdata.ps.sent[0] == (
            '{"event": "subscribe", '
            '"message": {"request_id": 1, "message": "newblock"}}'
        )

        # subscribeAddresses
        ddb.subscribeAddresses(["new_one"], addrReceiver)
        assert ddb.dcrdata.ps.sent[1] == (
            '{"event": "subscribe", '
            '"message": {"request_id": 1, "message": "address:new_one"}}'
        )

        # pubsubSignal
        assert ddb.pubsubSignal(dcrdata.WS_DONE) is None
        assert ddb.pubsubSignal(dict(event="subscribeResp")) is None
        assert ddb.pubsubSignal(dict(event="ping")) is None
        assert ddb.pubsubSignal(dict(event="unknown")) is None
        # pubsubSignal address
        ddb.subscribeAddresses(["the_address"], addrReceiver)
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

    def test_utxos(self, http_get_post):
        preload_api_list(http_get_post)
        http_get_post(f"{API_URL}/block/best", dict(height=1))
        ddb = DcrdataBlockchain(":memory:", testnet, BASE_URL)

        # txVout error
        with pytest.raises(DecredError):
            ddb.txVout(self.txs[2][0], 0).satoshis

        # processNewUTXO
        # Preload tx and tinfo.
        txURL = f"{API_URL}/tx/hex/{self.txs[1][0]}"
        http_get_post(txURL, self.txs[1][1])
        tinfoURL = f"{API_URL}/tx/{self.utxos[1]['txid']}/tinfo"
        http_get_post(tinfoURL, self.tinfo)
        utxo = ddb.processNewUTXO(self.utxos[1])
        assert utxo.tinfo.purchaseBlock.hash == reversed(
            ByteArray(self.tinfo["purchase_block"]["hash"])
        )

        # UTXOs
        assert len(ddb.UTXOs([])) == 0

        # Precompute the UTXO data.
        addrs = [utxo["address"] for utxo in self.utxos]
        addrStr = ",".join(addrs)
        utxoURL = f"{INSIGHT_URL}/addr/{addrStr}/utxo"

        # Preload the UTXOs but not the txs.
        http_get_post(utxoURL, self.utxos)
        with pytest.raises(DecredError):
            ddb.UTXOs(addrs)

        # Preload both the UTXOs and the txs.
        http_get_post(utxoURL, self.utxos)
        for txid, tx in self.txs:
            txURL = f"{API_URL}/tx/hex/{txid}"
            http_get_post(txURL, tx)
        assert len(ddb.UTXOs(addrs)) == 3

        # txidsForAddr
        txsURL = f"{INSIGHT_URL}/addr/the_address"
        # No transactions for an address.
        http_get_post(txsURL, {})
        assert ddb.txidsForAddr("the_address") == []
        # Some transactions for an address.
        http_get_post(txsURL, {"transactions": ["tx1"]})
        assert ddb.txidsForAddr("the_address") == ["tx1"]

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
        txURL = f"{API_URL}/tx/{self.txs[2][0]}"
        decodedTx = {"block": {"blockhash": self.blockHash}}
        http_get_post(txURL, decodedTx)
        headerURL = f"{API_URL}/block/hash/{self.blockHash}/header/raw"
        http_get_post(headerURL, self.blockHeader)
        assert ddb.confirmUTXO(utxo) is True

    def test_blocks(self, http_get_post):
        preload_api_list(http_get_post)
        http_get_post(f"{API_URL}/block/best", dict(height=1))
        ddb = DcrdataBlockchain(":memory:", testnet, BASE_URL)

        # blockHeader
        with pytest.raises(DecredError):
            ddb.blockHeader(self.blockHash)

        # blockHeaderByHeight
        with pytest.raises(DecredError):
            ddb.blockHeaderByHeight(self.blockHeight).id()
        # Preload the block header.
        headerURL = f"{API_URL}/block/{self.blockHeight}/header/raw"
        http_get_post(headerURL, self.blockHeader)
        assert ddb.blockHeaderByHeight(self.blockHeight).id() == self.blockHash
        # Exercise the database code.
        assert ddb.blockHeaderByHeight(self.blockHeight).id() == self.blockHash

        # blockForTx
        # Preload the first broken decoded tx.
        txURL = f"{API_URL}/tx/{self.txs[2][0]}"
        decodedTx = {"block": {}}
        http_get_post(txURL, decodedTx)
        assert ddb.blockForTx(self.txs[2][0]) is None
        # Preload the second broken decoded tx.
        txURL = f"{API_URL}/tx/{self.txs[2][0]}"
        decodedTx = {"block": {"blockhash": ""}}
        http_get_post(txURL, decodedTx)
        assert ddb.blockForTx(self.txs[2][0]) is None
        # Preload the right decoded tx.
        txURL = f"{API_URL}/tx/{self.txs[2][0]}"
        decodedTx = {"block": {"blockhash": self.blockHash}}
        http_get_post(txURL, decodedTx)
        assert ddb.blockForTx(self.txs[2][0]).height == self.blockHeight
        # Preload the block header.
        headerURL = f"{API_URL}/block/hash/{self.blockHash}/header/raw"
        http_get_post(headerURL, self.blockHeader)
        assert ddb.blockForTx(self.txs[2][0]).hash() == reversed(
            ByteArray(self.blockHash)
        )
        # Exercise the database code.
        assert ddb.blockForTx(self.txs[2][0]).hash() == reversed(
            ByteArray(self.blockHash)
        )

    def test_for_tx(self, http_get_post):
        preload_api_list(http_get_post)
        http_get_post(f"{API_URL}/block/best", dict(height=1))
        ddb = DcrdataBlockchain(":memory:", testnet, BASE_URL)

        # tinyBlockForTx
        # Preload the broken decoded tx.
        txURL = f"{API_URL}/tx/{self.txs[2][0]}"
        decodedTx = {"block": {}}
        http_get_post(txURL, decodedTx)
        assert ddb.tinyBlockForTx(self.txs[2][0]) is None
        # Preload the right decoded tx.
        txURL = f"{API_URL}/tx/{self.txs[2][0]}"
        decodedTx = {"block": {"blockhash": self.blockHash}}
        http_get_post(txURL, decodedTx)
        # Preload the block header.
        headerURL = f"{API_URL}/block/hash/{self.blockHash}/header/raw"
        http_get_post(headerURL, self.blockHeader)
        assert ddb.tinyBlockForTx(self.txs[2][0]).hash == reversed(
            ByteArray(self.blockHash)
        )

        # ticketForTx
        # Preload the non-ticket tx.
        txURL = f"{API_URL}/tx/hex/{self.txs[2][0]}"
        http_get_post(txURL, self.txs[2][1])
        with pytest.raises(DecredError):
            ddb.ticketForTx(self.txs[2][0], nets.mainnet)
        # Preload the ticket decoded tx.
        blockHash = self.tinfo["purchase_block"]["hash"]
        txURL = f"{API_URL}/tx/{self.txs[1][0]}"
        decodedTx = {"block": {"blockhash": blockHash}}
        http_get_post(txURL, decodedTx)
        # Preload tx and tinfo.
        txURL = f"{API_URL}/tx/hex/{self.txs[1][0]}"
        http_get_post(txURL, self.txs[1][1])
        tinfoURL = f"{API_URL}/tx/{self.utxos[1]['txid']}/tinfo"
        http_get_post(tinfoURL, self.tinfo)
        # Preload the block header.
        headerURL = f"{API_URL}/block/hash/{blockHash}/header/raw"
        http_get_post(headerURL, self.blockHeader)
        assert ddb.ticketForTx(self.txs[1][0], nets.mainnet).txid == self.txs[1][0]

        # ticketInfoForSpendingTx
        # Preload the txs.
        for txid, tx in self.txs:
            txURL = f"{API_URL}/tx/hex/{txid}"
            http_get_post(txURL, tx)
        txURL = f"{API_URL}/tx/{self.txs[3][0]}"
        blockHash = "00000000000000002847702f35b9227d27191d1858a7eccb94858c8f58f1066b"
        decodedTx = {"block": {"blockhash": blockHash}}
        http_get_post(txURL, decodedTx)
        blockHeader = {
            "hex": (
                "0700000037ef9650679e18f27a50f7395999b799917d567f7bcab60900000"
                "000000000008f4526c6c52f88a4b78177da200fe59e73ffd43d5d48cfecca"
                "63cbcdd6d5fbf8f8139bc051bd24ceecb4a5d569ee1c2c98ec74e52314cb0"
                "45fb3aea70d998de601006eb074d99aa405000200c2a4000038d93118b341"
                "394b030000001184060012070100d9a4565e25e9ec1324cbad03e593b65e3"
                "b1e0002000000000000000000000000000000000000000007000000"
            ),
        }
        headerURL = f"{API_URL}/block/hash/{blockHash}/header/raw"
        http_get_post(headerURL, blockHeader)
        assert (
            ddb.ticketInfoForSpendingTx(self.txs[2][0], nets.mainnet).maturityHeight
            == self.blockHeight - 1
        )

    def test_addrsHaveTxs(self, http_get_post):
        preload_api_list(http_get_post)
        http_get_post(f"{API_URL}/block/best", dict(height=1))
        addr = "someaddr"
        res = dict(items=[1])
        http_get_post(f"{INSIGHT_URL}/addrs/{addr}/txs?from=0&to=1", res)
        ddb = DcrdataBlockchain(":memory:", testnet, BASE_URL)
        assert ddb.addrsHaveTxs([addr])

        res["items"] = []
        http_get_post(f"{INSIGHT_URL}/addrs/{addr}/txs?from=0&to=1", res)
        assert not ddb.addrsHaveTxs([addr])

    def test_changeServer(self, http_get_post, monkeypatch):
        monkeypatch.setattr(ws, "Client", MockWebSocketClient)
        preload_api_list(http_get_post)
        http_get_post(f"{API_URL}/block/best", dict(height=1))
        ddb = DcrdataBlockchain(":memory:", testnet, BASE_URL)
        ddb.subscribeBlocks(lambda sig: True)
        ddb.subscribeAddresses(["addr_1", "addr_2"], lambda a, tx: True)

        preload_api_list(http_get_post, baseURL="https://thisurl.org/api")
        http_get_post(f"https://thisurl.org/api/block/best", dict(height=1))
        ddb.changeServer("https://thisurl.org/")
        assert ddb.dcrdata.baseURL == "https://thisurl.org/"
