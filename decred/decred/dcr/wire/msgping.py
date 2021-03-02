"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

Based on dcrd MsgPing.
"""

from decred.decred.util.encode import ByteArray


CmdPing = "ping"

NonceLength = 8


class MsgPing:
    """
    MsgPing implements the Message API and represents a Decred ping message.

    For versions BIP0031Version and earlier, it is used primarily to confirm
    that a connection is still valid.  A transmission error is typically
    interpreted as a closed connection and that the peer should be removed.
    For versions AFTER BIP0031Version it contains an identifier which can be
    returned in the pong message to determine network timing.

    The payload for this message just consists of a nonce used for identifying
    it later.
    """

    def __init__(self, nonce):
        """
        Args:
            nonce (int): A value unique to each ping message.
        """
        self.nonce = nonce

    @staticmethod
    def btcDecode(b, pver):
        """
        btcDecode decodes b using the Decred protocol encoding into the
        receiver. This is part of the Message API.

        Args:
            b (ByteArray): The encoded MsgPing.
            pver (int): The protocol version. Unused.

        Returns:
            MsgPing: The MsgPing.
        """
        return MsgPing(nonce=b.unLittle().int())

    def btcEncode(self, pver):
        """
        btcEncode encodes the receiver using the Decred protocol encoding.
        This is part of the Message API.

        Args:
            pver (int): The protocol version. Unused.

        Returns:
            ByteArray: The encoded MsgPing
        """
        return ByteArray(self.nonce, length=8).littleEndian()

    @staticmethod
    def command():
        """
        The protocol command string for the message.  This is part of the
        Message API.

        Returns:
            str: The command string.
        """
        return CmdPing

    @staticmethod
    def maxPayloadLength(pver):
        """
        The maximum length the payload can be for the receiver.  This is part of
        the Message API.

        Args:
            pver (int): The protocol version. Unused.

        Returns:
            int: The maximum payload length.
        """
        return NonceLength
