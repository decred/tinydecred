"""
Copyright (c) 2020, the Decred developers
See LICENSE for details

Tests use the "http_get_post" fixture in conftest.py .
"""

import json
from pathlib import Path

import pytest

from decred.crypto import opcode
from decred.dcr import txscript
from decred.dcr.dcrdata import (
    DcrdataClient,
    DcrdataError,
    DcrdataPath,
    DecredError,
    checkOutput,
    makeOutputs,
)
from decred.dcr.nets import testnet
from decred.dcr.wire import msgtx
from decred.util.encode import ByteArray


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


def make_dcrdataclient(http_get_post):
    # Load the list of API calls.
    data_file = Path(__file__).resolve().parent / "test-data" / "dcrdata.json"
    with open(data_file) as f:
        api_list = json.loads(f.read())

    # Queue the list of API calls.
    base_url = "https://example.org/"
    http_get_post(f"{base_url}api/list", api_list)

    ddc = DcrdataClient(base_url)

    # Set the mock WebsocketClient.
    ddc.ps = MockWebsocketClient()

    return ddc


class TestDcrdataClient:
    def test_misc(self, http_get_post):
        ddc = make_dcrdataclient(http_get_post)

        assert len(ddc.listEntries) == 84
        assert len(ddc.subscribedAddresses) == 0
        assert ddc.endpointList()[0] == ddc.listEntries[0][1]
        assert ddc.endpointGuide() is None

    def test_subscriptions(self, http_get_post):
        ddc = make_dcrdataclient(http_get_post)

        ddc.subscribedAddresses = ["already_there"]
        ddc.subscribeAddresses(["already_there", "new_one"])
        assert ddc.ps.sent[0]["message"]["message"] == "address:new_one"

        ddc.ps.sent = []
        ddc.subscribeBlocks()
        assert ddc.ps.sent[0]["message"]["message"] == "newblock"

    def test_static(self):
        assert DcrdataClient.timeStringToUnix("1970-01-01 00:00:00") == 0
        assert DcrdataClient.RFC3339toUnix("1970-01-01T00:00:00Z") == 0
