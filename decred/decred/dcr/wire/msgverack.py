"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

Based on dcrd MsgVerAck.
"""

from decred.util.encode import ByteArray


CmdVerAck = "verack"


class MsgVerAck:
    """
    MsgVerAck defines a Decred verack message which is used for a peer to
    acknowledge a version message (MsgVersion) after it has used the information
    to negotiate parameters.  It implements the Message API.

    This message has no payload.
    """

    @staticmethod
    def btcDecode(b, pver):
        """
        Decode b using the Decred protocol encoding into the receiver. This is
        part of the Message API.

        Args:
            b (ByteArray): The encoded MsgVerAck. Unused, since MsgVerAck has
                a zero-length payload.
            pver (int): The protocol version. Unused.
        """
        return MsgVerAck()

    def btcEncode(self, pver):
        """
        btcEncode encodes the MsgVerAck using the Decred protocol encoding. This
        is part of the Message API.

        Args:
            pver (int): The protocol version. Unused.

        Returns:
            ByteArray: The encoded MsgVerAck.
        """
        return ByteArray()

    def command(self):
        """
        The protocol command string for the message.  This is part of the
        Message API.

        Returns:
            str: The command string.
        """
        return CmdVerAck

    def maxPayloadLength(self, pver):
        """
        The maximum length the payload can be for the receiver. This is part of
        the Message API.

        Args:
            pver (int): The protocol version. Unused.

        Returns:
            int: The maximum payload length.
        """
        return 0
