"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

Based on dcrd MsgPing.
"""

import random

from decred.dcr.wire import wire
from decred.dcr.wire.msgpong import MsgPong
from decred.util.encode import ByteArray


def test_Pong():
    """
    Test the MsgPong API against the latest protocol version.
    """
    pver = wire.ProtocolVersion

    nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
    msg = MsgPong(nonce)
    assert msg.nonce == nonce

    # Ensure the command is expected value.
    assert msg.command() == "pong"

    # Ensure max payload is expected value for latest protocol version.
    maxPayload = msg.maxPayloadLength(pver)
    assert maxPayload == 8

    # Ensure max payload length is not more than MaxMessagePayload.
    assert maxPayload <= wire.MaxMessagePayload

    # Test encode with latest protocol version.
    b = msg.btcEncode(pver)

    # Test decode with latest protocol version.
    reMsg = MsgPong.btcDecode(b, pver)

    # Ensure nonce is the same.
    assert msg.nonce == reMsg.nonce


def test_PongWire():
    """
    Test the MsgPong wire encode and decode for various protocol versions.
    """
    nonce = 0x1E0F3
    msg = MsgPong(nonce)
    msgEncoded = ByteArray("f3e0010000000000")

    # Encode the message to wire format.
    b = msg.btcEncode(wire.ProtocolVersion)
    assert b == msgEncoded

    # Decode the message from wire format.
    reMsg = MsgPong.btcDecode(b, wire.ProtocolVersion)
    assert reMsg.nonce == nonce
