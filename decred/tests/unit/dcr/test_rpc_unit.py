"""
Copyright (c) 2020, the Decred developers
See LICENSE for details

Tests use the "http_get_post" and "MockWebSocketClient" fixtures in conftest.py
"""

import pytest

from decred import DecredError
from decred.dcr import rpc
from decred.util import ws
from decred.util.encode import ByteArray


def test_Client(http_get_post):
    http_get_post(
        (
            "https://example.org",
            "{'jsonrpc': '2.0', 'id': 0, 'method': 'stop', 'params': ()}",
        ),
        '{"id": 0, "result": "dcrd stopping.", "error": ""}',
    )
    client = rpc.Client(url="https://example.org", user="username", pw="password",)
    assert client.stop() == "dcrd stopping."


GET_ADDED_NODE_INFO_RESULT_ADDR_RAW = dict(address="127.0.0.1", connected="false")


def test_GetAddedNodeInfoResultAddr():
    # Parsed values are the same as the raw ones.
    GET_ADDED_NODE_INFO_RESULT_ADDR_PARSED = GET_ADDED_NODE_INFO_RESULT_ADDR_RAW
    GET_ADDED_NODE_INFO_RESULT_ADDR_ATTRS = ("address", "connected")

    do_test(
        class_=rpc.GetAddedNodeInfoResultAddr,
        raw=GET_ADDED_NODE_INFO_RESULT_ADDR_RAW,
        parsed=GET_ADDED_NODE_INFO_RESULT_ADDR_PARSED,
        attrs=GET_ADDED_NODE_INFO_RESULT_ADDR_ATTRS,
    )


def test_GetAddedNodeInfoResult():
    GET_ADDED_NODE_INFO_RESULT_RAW = dict(
        addednode="127.0.0.1",
        connected=False,
        addresses=[GET_ADDED_NODE_INFO_RESULT_ADDR_RAW],
    )
    # Make a copy of the raw dict in order not to overwrite it.
    GET_ADDED_NODE_INFO_RESULT_PARSED = dict(GET_ADDED_NODE_INFO_RESULT_RAW)
    GET_ADDED_NODE_INFO_RESULT_PARSED["addresses"] = [
        rpc.GetAddedNodeInfoResultAddr.parse(GET_ADDED_NODE_INFO_RESULT_ADDR_RAW)
    ]
    GET_ADDED_NODE_INFO_RESULT_ATTRS = ("addedNode", "connected", "addresses")

    do_test(
        class_=rpc.GetAddedNodeInfoResult,
        raw=GET_ADDED_NODE_INFO_RESULT_RAW,
        parsed=GET_ADDED_NODE_INFO_RESULT_PARSED,
        attrs=GET_ADDED_NODE_INFO_RESULT_ATTRS,
    )


def test_GetWorkResult():
    GET_WORK_RESULT_RAW = dict(data=[0, 1], target=[2, 3])
    GET_WORK_RESULT_PARSED = dict(data=ByteArray([0, 1]), target=ByteArray([2, 3]))
    GET_WORK_RESULT_ATTRS = ("data", "target")

    do_test(
        class_=rpc.GetWorkResult,
        raw=GET_WORK_RESULT_RAW,
        parsed=GET_WORK_RESULT_PARSED,
        attrs=GET_WORK_RESULT_ATTRS,
    )


def test_PrevOut():
    PREV_OUT_RAW = dict(value=1.0, addresses=["addr"])
    # Parsed values are the same as the raw ones.
    PREV_OUT_PARSED = PREV_OUT_RAW
    PREV_OUT_ATTRS = ("value", "addresses")

    do_test(
        class_=rpc.PrevOut,
        raw=PREV_OUT_RAW,
        parsed=PREV_OUT_PARSED,
        attrs=PREV_OUT_ATTRS,
    )


def do_test(class_, raw, parsed, attrs):
    """
    Iterate over the attributes defined in <class_>_ATTRS and make sure that
    the values generated by its "parse" method are the same as the ones in
    <class_>_PARSED.

    Separate <class_>_ATTRS tuples are needed because the attribute names are
    different from the keys of the dicts the values are gotten from.
    """
    obj = class_.parse(raw)
    for attr in attrs:
        assert getattr(obj, attr) == parsed[attr.lower()]


def test_eq():
    address = rpc.GetAddedNodeInfoResultAddr.parse(GET_ADDED_NODE_INFO_RESULT_ADDR_RAW)
    assert address != object()
    assert address == address


def test_WebsocketClient(monkeypatch, MockWebSocketClient):

    monkeypatch.setattr(ws, "Client", MockWebSocketClient)

    wsClient = rpc.WebsocketClient(
        url="https://example.org", user="username", pw="password",
    )
    wsClient.requestTimeout = 1

    msg = '{"id": -1, "result": "", "error": "error"}'
    assert wsClient.on_message(msg) is None

    msg = "not_json"
    assert wsClient.on_message(msg) is None

    assert wsClient.call("no_reply") is None

    def send_with_reply(msg):
        wsClient.ws.on_message('{"id": 1, "result": "", "error": "error"}')

    # The response is sent back right away by the above class.
    wsClient.ws.send = send_with_reply
    with pytest.raises(DecredError):
        wsClient.call("no_such_method")

    assert wsClient.on_close(wsClient.ws) is None

    assert wsClient.on_error("error") is None
