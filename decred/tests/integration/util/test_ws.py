"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

from queue import Queue
import threading
import time
from urllib.parse import urlunsplit

import pytest
import websocket
from websocket_server import WebsocketServer

from decred.util import ws


HOST = "localhost"
PORT = 53791
URL = urlunsplit(("http", f"{HOST}:{PORT}", "/", "", ""))
QUIT = "QUIT"
HELLO = "HELLO"
YO = "YO"
CLOSE_HANDSHAKE = bytearray([0x88, 0])


def test_websocket():
    """
    Start a ws.Client and check basic functionality.
    """
    serverQ = Queue(1)
    clientQ = Queue(1)
    errorQ = Queue(1)

    def receive(client, server, message):
        if message == HELLO:
            server.send_message(client, YO)
        elif message == QUIT:
            client["handler"].request.send(CLOSE_HANDSHAKE)
            server.shutdown()
        serverQ.put(message)

    server = WebsocketServer(PORT, HOST)
    server.set_fn_message_received(receive)
    serverThread = threading.Thread(None, server.run_forever)
    serverThread.start()
    time.sleep(1)

    class test:
        was_opened = False
        was_closed = False

    def on_open(ws):
        test.was_opened = True

    def on_message(ws, msg):
        clientQ.put(msg, timeout=1)

    def on_close(ws):
        test.was_closed = True

    def on_error(ws, error):
        errorQ.put(error, timeout=1)

    def client(url):
        return ws.Client(
            url=url,
            on_open=on_open,
            on_message=on_message,
            on_close=on_close,
            on_error=on_error,
        )

    try:
        # Send a hello and make sure it is received.
        cl = client(URL)
        assert test.was_opened

        cl.send(HELLO)
        msg = serverQ.get(timeout=1)
        assert msg == HELLO

        # Make sure we got the response.
        msg = clientQ.get(timeout=1)
        assert msg == YO

        # Trigger a server shutdown.
        cl.send(QUIT)
        serverQ.get(timeout=1)

        # Make sure the close callback was called.
        assert test.was_closed

        # Make sure a send fails.
        with pytest.raises(websocket.WebSocketConnectionClosedException):
            cl.send("should be closed")

        # Force a client error and ensure it comes through the callback.
        assert errorQ.empty()
        cl = client("notaurl")
        errorQ.get(timeout=1)

    except Exception as e:
        server.shutdown()
        raise e
    finally:
        cl.close()

    serverThread.join()
