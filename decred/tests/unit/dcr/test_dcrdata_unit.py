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
from decred.dcr import txscript
# Use after #82 is merged.
# from decred.dcr import agenda
from decred.dcr.dcrdata import (
    DcrdataBlockchain,
    DcrdataClient,
    DcrdataError,
    DcrdataPath,
    checkOutput,
    makeOutputs,
)
from decred.dcr.dcrdata import AgendasInfo  # Remove after #82 is merged.
from decred.dcr.nets import testnet
from decred.dcr.wire import msgtx
from decred.util.encode import ByteArray


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
    base_url = "https://example.org/"
    http_get_post(f"{base_url}api/list", api_list)

    return base_url


class TestDcrdataClient:
    def test_misc(self, http_get_post, capsys):
        base_url = preload_api_list(http_get_post)
        ddc = DcrdataClient(base_url)

        assert len(ddc.listEntries) == 84
        assert len(ddc.subscribedAddresses) == 0
        assert ddc.endpointList()[0] == ddc.listEntries[0][1]

        # This prints to stdout.
        ddc.endpointGuide()
        out, err = capsys.readouterr()
        assert len(out.splitlines()) == 84

    def test_subscriptions(self, http_get_post):
        base_url = preload_api_list(http_get_post)
        ddc = DcrdataClient(base_url)

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
    def test_subscriptions(self, http_get_post, tmp_path):

        # Exception in updateTip.
        base_url = preload_api_list(http_get_post)
        with pytest.raises(DecredError):
            DcrdataBlockchain(str(tmp_path / "test.db"), testnet, base_url)

        # Successful creation.
        base_url = preload_api_list(http_get_post)
        http_get_post(f"{base_url}api/block/best", 1)
        ddb = DcrdataBlockchain(str(tmp_path / "test.db"), testnet, base_url)
        assert ddb.tip == 1

        # Set the mock WebsocketClient.
        ddb.dcrdata.ps = MockWebsocketClient()

        # Subscribes.
        def receiver(obj):
            print("msg: %s" % repr(obj))

        ddb.subscribeBlocks(receiver)
        assert ddb.dcrdata.ps.sent[0]["message"]["message"] == "newblock"

        # Exception in subscribeAddresses.
        with pytest.raises(DecredError):
            ddb.subscribeAddresses([])

        ddb.dcrdata.ps.sent = []
        ddb.subscribeAddresses(["new_one"], receiver)
        assert ddb.dcrdata.ps.sent[0]["message"]["message"] == "address:new_one"

        # getAgendasInfo.
        http_get_post(f"{base_url}api/stake/vote/info", AGENDAS_INFO_RAW)
        agsinfo = ddb.getAgendasInfo()
        # Use after #82 is merged.
        # assert isinstance(agsinfo, agenda.AgendasInfo)
        assert isinstance(agsinfo, AgendasInfo)
