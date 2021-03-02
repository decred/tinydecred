"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

Based on dcrd MsgPing.
"""

from decred.decred.util.encode import ByteArray


CmdPong = "pong"

NonceLength = 8


class MsgPong:
    """
    MsgPong implements the Message API and represents a Decred pong message
    which is used primarily to confirm that a connection is still valid in
    response to a Decred ping message (MsgPing).

    This message was not added until protocol versions AFTER BIP0031Version.
    """

    def __init__(self, nonce):
        """
        Args:
            nonce (int): Unique value associated with associated with a specific
                ping message.
        """
        self.nonce = nonce

    @staticmethod
    def btcDecode(b, pver):
        """
        btcDecode decodes b using the Decred protocol encoding into the receiver. This
        is part of the Message API.

        Args:
            b (ByteArray): The encoded MsgPong.
            pver (int): The protocol version. Unused.

        Returns:
            MsgPong. The MsgPong.
        """
        return MsgPong(nonce=b.unLittle().int())

    def btcEncode(self, pver):
        """
        btcEncode encodes the receiver using the Decred protocol encoding.
        This is part of the Message API.

        Args:
            pver (int): The protocol version. Unused.

        Returns:
            ByteArray: The encoded MsgPong
        """
        return ByteArray(self.nonce, length=8).littleEndian()

    @staticmethod
    def command():
        """
        command returns the protocol command string for the message.  This is
        part of the Message API.

        Returns:
            str: The command string.
        """
        return CmdPong

    @staticmethod
    def maxPayloadLength(pver):
        """
        maxPayloadLength returns the maximum length the payload can be for the
        receiver.  This is part of the Message API.

        Args:
            pver (int): The protocol version. Unused.

        Returns:
            int: The maximum payload length.
        """
        return NonceLength
