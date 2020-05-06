"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

Based on dcrd MsgPing.
"""

import random

from decred.dcr.wire import wire
from decred.dcr.wire.msgping import MsgPing
from decred.util.encode import ByteArray


def test_Ping():
    """
    Test the MsgPing API against the latest protocol version.
    """
    pver = wire.ProtocolVersion

    # Ensure we get the same nonce back out.
    nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
    msg = MsgPing(nonce=nonce)
    assert msg.nonce == nonce

    # Ensure the command is expected value.
    assert msg.command() == "ping"

    maxPayload = msg.maxPayloadLength(pver)
    # Ensure max payload is expected value for latest protocol version.
    assert maxPayload == 8

    # Ensure max payload length is not more than MaxMessagePayload.
    assert maxPayload <= wire.MaxMessagePayload


def test_PingWire():
    """
    Test the MsgPing wire encode and decode for various protocol versions.
    """
    nonce = 0x1E0F3
    msg = MsgPing(nonce)
    msgEncoded = ByteArray("f3e0010000000000")

    # Encode the message to wire format.
    b = msg.btcEncode(wire.ProtocolVersion)
    assert b == msgEncoded

    # Decode the message from wire format.
    reMsg = MsgPing.btcDecode(b, wire.ProtocolVersion)
    assert reMsg.nonce == nonce
