"""
Copyright (c) 2020, the Decred developers
See LICENSE for details

Tests use the "MockWebSocketClient_class" fixture in conftest.py .
"""

import pytest

from decred import DecredError
from decred.dcr import rpc
from decred.util import ws


def test_WebsocketClient(monkeypatch, MockWebSocketClient_class):

    monkeypatch.setattr(ws, "Client", MockWebSocketClient_class)

    wsClient = rpc.WebsocketClient(
        url="https://example.org",
        user="username",
        pw="password",
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
