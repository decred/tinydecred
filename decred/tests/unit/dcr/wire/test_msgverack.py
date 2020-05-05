"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.
"""

from decred.dcr.wire import wire
from decred.dcr.wire.msgverack import MsgVerAck
from decred.util.encode import ByteArray


def test_VerAck():
    """ Test the MsgVerAck API. """
    pver = wire.ProtocolVersion

    # Ensure the command is expected value.
    msg = MsgVerAck()
    assert msg.command() == "verack"

    # Ensure max payload is expected value.
    maxPayload = msg.maxPayloadLength(pver)
    assert msg.maxPayloadLength(pver) == 0

    # Ensure max payload length is not more than MaxMessagePayload.
    assert maxPayload <= wire.MaxMessagePayload


def test_VerAckWire():
    """
    Test the MsgVerAck wire encode and decode for various protocol versions.
    """
    msgVerAck = MsgVerAck()
    msgVerAckEncoded = ByteArray()

    # Encode the message to wire format.
    b = msgVerAck.btcEncode(wire.ProtocolVersion)
    assert b == msgVerAckEncoded

    # Decode the message from wire format. Just looking for exceptions.
    MsgVerAck.btcDecode(msgVerAckEncoded, wire.ProtocolVersion)
