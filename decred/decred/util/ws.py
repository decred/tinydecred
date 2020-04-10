"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import threading

import websocket


class Client(websocket.WebSocketApp):
    """
    A websocket client. On top of the base functionality offered by
    websocket.WebSocketApp, Client handles some initialization and shutdown
    related tasks.
    """

    def __init__(self, url, certPath=None, **k):
        """
        Args:
            url str: The websocket server URL.

        Additional keyword arguments are passed directly to the WebSocketApp
        constructor. The caller should provide callback functions for various
        events. The most common callbacks are listed here.

            on_open: Called at opening websocket. This function has one
                argument, the instance of Client.

            on_message: Called when data is received. on_message has 2
                arguments. The 1st argument is the instance of Client. The 2nd
                argument is the received message decoded (utf-8) as a str.

            on_error: Called when an exception is encountered. on_error has 2
                arguments. The 1st argument is the instance of Client. The 2nd
                argument is an Exception.

            on_close: Called when the connection is closed. This function has
                one argument, the instance of Client.
        """
        # The constructor will block until the initEvent is set so that the
        # Client is immediately usable by the caller.
        initEvent = threading.Event()

        cleanURL = url.replace("https:", "wss:").replace("http:", "ws:")

        user_open = k.pop("on_open", None)

        def on_open(ws):
            if user_open:
                user_open(ws)
            initEvent.set()

        user_close = k.pop("on_close", None)

        def on_close(ws):
            # Some initialization errors won't call on_open, but they will call
            # on_close, so set the initEvent here too.
            if user_close:
                user_close(ws)
            initEvent.set()

        super().__init__(cleanURL, on_open=on_open, on_close=on_close, **k)

        sslopt = {"ca_certs": certPath} if certPath else None

        self.thread = threading.Thread(
            None, self.run_forever, kwargs={"sslopt": sslopt}
        )
        self.thread.start()
        initEvent.wait()

    def close(self):
        """
        Close the connection and wait for shutdown.
        """
        super().close()
        if self.thread:
            self.thread.join(20)
            self.thread = None
