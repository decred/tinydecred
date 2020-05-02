"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.dcr.wire import netaddress, wire
from decred.util.encode import ByteArray


byteIP4 = bytes([127, 0, 0, 1])


def test_NetAddress():
    ip = "127.0.0.1"
    port = 8333

    # Test NewNetAddress.
    tcpAddr = netaddress.TCPAddr(ip, port)
    na = netaddress.newNetAddress(tcpAddr, 0)

    # Ensure we get the same ip, port, and services back out.
    assert byteIP4 == na.ip
    assert port == na.port
    assert na.services == 0
    assert not na.hasService(wire.SFNodeNetwork)

    # Ensure adding the full service node flag works.
    na.addService(wire.SFNodeNetwork)
    assert na.services == wire.SFNodeNetwork
    assert na.hasService(wire.SFNodeNetwork)

    # Ensure max payload is expected value for latest protocol version.
    wantPayload = 30
    maxPayload = netaddress.MaxNetAddressPayload
    assert maxPayload == wantPayload

    # Ensure max payload length is not more than MaxMessagePayload.
    assert maxPayload <= wire.MaxMessagePayload


def test_NetAddressWire():
    """
    test the NetAddress wire encode and decode for various protocol versions and
    timestamp flag combinations.
    """
    # baseNetAddr is used in the various tests as a baseline NetAddress.
    baseNetAddr = netaddress.NetAddress(
        ip="127.0.0.1",
        port=8333,
        services=wire.SFNodeNetwork,
        stamp=0x495FAB29,  # 2009-01-03 12:15:05 -0600 CST
    )

    # baseNetAddrNoTS is baseNetAddr with a zero value for the timestamp.
    baseNetAddrNoTS = netaddress.NetAddress(
        ip=baseNetAddr.ip,
        port=baseNetAddr.port,
        services=baseNetAddr.services,
        stamp=0,
    )

    # fmt: off
    # baseNetAddrEncoded is the wire encoded bytes of baseNetAddr.
    baseNetAddrEncoded = ByteArray([
        0x29, 0xab, 0x5f, 0x49, # Timestamp
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, # IP 127.0.0.1
        0x20, 0x8d, # Port 8333 in big-endian
    ])

    # baseNetAddrNoTSEncoded is the wire encoded bytes of baseNetAddrNoTS.
    baseNetAddrNoTSEncoded = ByteArray([
        # No timestamp
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, # IP 127.0.0.1
        0x20, 0x8d, # Port 8333 in big-endian
    ])
    # fmt: on

    """
    addrIn NetAddress to encode
    out    Expected decoded NetAddress
    ts     Include timestamp?
    buf    Wire encoding
    pver   Protoc
    """

    tests = [
        # Latest protocol version without ts flag.
        dict(
            addrIn=baseNetAddr,
            out=baseNetAddrNoTS,
            ts=False,
            buf=baseNetAddrNoTSEncoded,
            pver=wire.ProtocolVersion,
        ),
        # Latest protocol version with ts flag.
        dict(
            addrIn=baseNetAddr,
            out=baseNetAddr,
            ts=True,
            buf=baseNetAddrEncoded,
            pver=wire.ProtocolVersion,
        ),
    ]

    for test in tests:
        # Encode to wire format.
        b = netaddress.writeNetAddress(test["addrIn"], test["ts"])

        assert b == test["buf"]

        # Decode the message from wire format.
        na = netaddress.readNetAddress(test["buf"], test["ts"])

        assert byteIP4 == test["out"].ip
        assert na.port == test["out"].port
        assert na.services == test["out"].services
        assert na.timestamp == test["out"].timestamp

    baseNetAddr.ip = None
    b = netaddress.writeNetAddress(baseNetAddr, True)
    reNA = netaddress.readNetAddress(b, True)
    assert reNA.ip == ByteArray(length=16)

    # make sure a ipv6 address parses without an exception.
    netaddress.NetAddress(
        ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        port=8333,
        services=wire.SFNodeNetwork,
        stamp=0x495FAB29,  # 2009-01-03 12:15:05 -0600 CST
    )


def test_NetAddressDecodeErrors():
    """
    Peform negative tests against wire encode and decode NetAddress to confirm
    error paths work correctly.
    """

    # baseNetAddr is used in the various tests as a baseline NetAddress.
    baseNetAddr = netaddress.NetAddress(
        ip="127.0.0.1",
        port=8333,
        services=wire.SFNodeNetwork,
        stamp=0x495FAB29,  # 2009-01-03 12:15:05 -0600 CST
    )

    bufWithTime = netaddress.writeNetAddress(baseNetAddr, True)
    bufWithoutTime = netaddress.writeNetAddress(baseNetAddr, False)

    tests = [
        (bufWithTime[:-1], True),
        (bufWithTime + [0], True),
        (bufWithoutTime[:-1], False),
        (bufWithoutTime + [0], False),
        (ByteArray(), True),
    ]

    for buf, hasStamp in tests:
        with pytest.raises(DecredError):
            netaddress.readNetAddress(buf, hasStamp)
