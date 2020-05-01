"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import random

import pytest

from decred import DecredError
from decred.dcr.wire import msgversion, netaddress, wire
from decred.util.encode import ByteArray


def sameNetAddress(one, two):
    return (
        one.timestamp == two.timestamp
        and one.ip == two.ip
        and one.port == two.port
        and one.services == two.services
    )


def sameMsgVersion(one, two):
    return (
        one.protocolVersion == two.protocolVersion
        and one.services == two.services
        and one.timestamp == two.timestamp
        and sameNetAddress(one.addrYou, two.addrYou)
        and sameNetAddress(one.addrMe, two.addrMe)
        and one.nonce == two.nonce
        and one.userAgent == two.userAgent
        and one.lastBlock == two.lastBlock
        and one.disableRelayTx == two.disableRelayTx
    )


def baseVersionEncoded():
    # fmt: off
    return ByteArray([
        0x62, 0xea, 0x00, 0x00, # Protocol version 60002
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00, # 64-bit Timestamp
        # AddrYou -- No timestamp for NetAddress in version message
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x00, 0x01, # IP 192.168.0.1
        0x20, 0x8d, # Port 8333 in big-endian
        # AddrMe -- No timestamp for NetAddress in version message
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, # IP 127.0.0.1
        0x20, 0x8d, # Port 8333 in big-endian
        0xf3, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, # Nonce
        0x10, # Varint for user agent length
        0x2f, 0x64, 0x63, 0x72, 0x64, 0x74, 0x65, 0x73,
        0x74, 0x3a, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x2f, # User agent
        0xfa, 0x92, 0x03, 0x00, # Last block
    ])
    # fmt: on


def baseVersion():
    return msgversion.MsgVersion(
        protocolVersion=60002,
        services=wire.SFNodeNetwork,
        timestamp=0x495FAB29,
        addrYou=netaddress.NetAddress(
            ip="192.168.0.1", port=8333, services=wire.SFNodeNetwork, stamp=0,
        ),
        addrMe=netaddress.NetAddress(
            ip="127.0.0.1", port=8333, services=wire.SFNodeNetwork, stamp=0,
        ),
        nonce=123123,
        userAgent="/dcrdtest:0.0.1/",
        lastBlock=234234,
        disableRelayTx=False,
    )


def baseVersionBIP0037():
    v = baseVersion()
    v.protocolVersion = 70001
    return v


def baseVersionBIP0037Encoded():
    # fmt: off
    return ByteArray([
        0x71, 0x11, 0x01, 0x00, # Protocol version 70001
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00, # 64-bit Timestamp
        # AddrYou -- No timestamp for NetAddress in version message
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x00, 0x01, # IP 192.168.0.1
        0x20, 0x8d, # Port 8333 in big-endian
        # AddrMe -- No timestamp for NetAddress in version message
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # SFNodeNetwork
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, # IP 127.0.0.1
        0x20, 0x8d, # Port 8333 in big-endian
        0xf3, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, # Nonce
        0x10, # Varint for user agent length
        0x2f, 0x64, 0x63, 0x72, 0x64, 0x74, 0x65, 0x73,
        0x74, 0x3a, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x2f, # User agent
        0xfa, 0x92, 0x03, 0x00, # Last block
        0x01, # Relay tx
    ])
    # fmt: on


def test_MsgVersion():
    pver = wire.ProtocolVersion

    # Create version message data.
    lastBlock = 234234
    tcpAddrMe = netaddress.TCPAddr(ip="127.0.0.1", port=8333,)

    me = netaddress.newNetAddress(tcpAddrMe, wire.SFNodeNetwork)
    tcpAddrYou = netaddress.TCPAddr(ip="192.168.0.1", port=8333,)
    you = netaddress.newNetAddress(tcpAddrYou, wire.SFNodeNetwork)

    nonce = random.randint(0, 0xFFFFFFFF)

    # Ensure we get the correct data back out.
    msg = msgversion.newMsgVersion(me, you, nonce, lastBlock)
    assert msg.protocolVersion == pver

    assert sameNetAddress(msg.addrMe, me)
    assert sameNetAddress(msg.addrYou, you)
    assert msg.nonce == nonce
    assert msg.userAgent == msgversion.DefaultUserAgent
    assert msg.lastBlock == lastBlock
    assert not msg.disableRelayTx

    msg.addUserAgent("myclient", "1.2.3", "optional", "comments")
    customUserAgent = (
        msgversion.DefaultUserAgent + "myclient:1.2.3(optional; comments)/"
    )
    assert msg.userAgent == customUserAgent

    msg.addUserAgent("mygui", "3.4.5")
    customUserAgent += "mygui:3.4.5/"
    assert msg.userAgent == customUserAgent

    # accounting for ":", "/"
    with pytest.raises(DecredError):
        msg.addUserAgent(
            "t" * (msgversion.MaxUserAgentLen - len(customUserAgent) - 2 + 1), ""
        )

    # Version message should not have any services set by default.
    assert msg.services == 0
    assert not msg.hasService(wire.SFNodeNetwork)

    # Ensure the command is expected value.
    assert msg.command() == "version"

    # Ensure max payload is expected value.
    # Protocol version 4 bytes + services 8 bytes + timestamp 8 bytes +
    # remote and local net addresses + nonce 8 bytes + length of user agent
    # (varInt) + max allowed user agent length + last block 4 bytes +
    # relay transactions flag 1 byte.
    wantPayload = 358
    maxPayload = msg.maxPayloadLength(pver)
    assert maxPayload == wantPayload

    # Ensure max payload length is not more than MaxMessagePayload.
    assert maxPayload <= wire.MaxMessagePayload

    # Ensure adding the full service node flag works.
    msg.addService(wire.SFNodeNetwork)
    assert msg.services == wire.SFNodeNetwork
    assert msg.hasService(wire.SFNodeNetwork)

    # Use a fake connection.
    class fakeConn:
        localAddr = tcpAddrMe
        remoteAddr = tcpAddrYou

    msg = msgversion.newMsgVersionFromConn(fakeConn, nonce, lastBlock)

    # Ensure we get the correct connection data back out.
    assert msg.addrMe.ip == tcpAddrMe.ip
    assert msg.addrYou.ip == tcpAddrYou.ip


def test_VersionWire():
    """
    Test the MsgVersion wire encode and decode for various protocol versions.
    """
    # verRelayTxFalse and verRelayTxFalseEncoded is a version message as of
    # BIP0037Version with the transaction relay disabled.
    baseVersionBIP0037Copy = baseVersionBIP0037
    verRelayTxFalse = baseVersionBIP0037Copy
    verRelayTxFalse.disableRelayTx = True
    verRelayTxFalseEncoded = baseVersionBIP0037Encoded()
    verRelayTxFalseEncoded[-1] = 0

    # Encode the message to wire format.
    b = baseVersionBIP0037().btcEncode(wire.ProtocolVersion)
    assert b == baseVersionBIP0037Encoded()

    # Decode the message from wire format.
    msg = msgversion.MsgVersion.btcDecode(
        baseVersionBIP0037Encoded(), wire.ProtocolVersion
    )
    assert sameMsgVersion(msg, baseVersionBIP0037())


def test_VersionWireErrors():
    """
    Negative tests against wire encode and decode of MsgGetHeaders to confirm error
    paths work correctly.
    """
    # Use protocol version 60002 specifically here instead of the latest because
    # the test data is using bytes encoded with that protocol version.
    pver = 60002

    # Get a base version, and change the user agent to exceed max limits.
    bvc = baseVersion()
    exceedUAVer = bvc
    newUA = "/" + "t" * (msgversion.MaxUserAgentLen - 8 + 1) + ":0.0.1/"
    exceedUAVer.userAgent = newUA

    # Encode the new UA length as a varint.
    newUAVarIntBuf = wire.writeVarInt(pver, len(newUA))

    # Make a new buffer big enough to hold the base version plus the new
    # bytes for the bigger varint to hold the new size of the user agent
    # and the new user agent string.  Then stitch it all together.
    bvEnc = baseVersionEncoded()
    exceedUAVerEncoded = ByteArray()
    exceedUAVerEncoded += bvEnc[0:80]
    exceedUAVerEncoded += newUAVarIntBuf
    exceedUAVerEncoded += newUA.encode()
    exceedUAVerEncoded += bvEnc[97:100]

    with pytest.raises(DecredError):
        msgversion.MsgVersion.btcDecode(exceedUAVerEncoded, pver)

    bv = baseVersion()
    bv.userAgent = "t" * msgversion.MaxUserAgentLen + "1"

    with pytest.raises(DecredError):
        bv.btcEncode(pver)


def minimumMsgVersion():
    return msgversion.MsgVersion(
        protocolVersion=60002,
        services=wire.SFNodeNetwork,
        timestamp=0x495FAB29,
        addrYou=netaddress.NetAddress(
            ip="192.168.0.1", port=8333, services=wire.SFNodeNetwork, stamp=0,
        ),
        addrMe=netaddress.NetAddress(
            ip=ByteArray(length=16), port=0, services=0, stamp=0,
        ),
        nonce=0,
        userAgent="",
        lastBlock=0,
        disableRelayTx=False,
    )


def test_VersionOptionalFields():
    """
    Perform tests to ensure that an encoded version messages that omit optional
    fields are handled correctly.
    """
    # onlyRequiredVersion is a version message that only contains the
    # required versions and all other values set to their default values.
    onlyRequiredVersion = minimumMsgVersion()

    onlyRequiredVersionEncoded = baseVersionEncoded()[:-55]

    # addrMeVersion is a version message that contains all fields through
    # the AddrMe field.
    addrMe = netaddress.NetAddress(
        ip="127.0.0.1", port=8333, services=wire.SFNodeNetwork, stamp=0,
    )
    addrMeVersion = minimumMsgVersion()
    addrMeVersion.addrMe = addrMe

    addrMeVersionEncoded = baseVersionEncoded()[:-29]

    # nonceVersion is a version message that contains all fields through
    # the Nonce field.
    nonceVersion = minimumMsgVersion()
    nonceVersion.addrMe = addrMe
    nonceVersion.nonce = 123123  # 0x1e0f3
    nonceVersionEncoded = baseVersionEncoded()[:-21]

    # uaVersion is a version message that contains all fields through
    # the UserAgent field.
    uaVersion = minimumMsgVersion()
    uaVersion.addrMe = addrMe
    uaVersion.nonce = 123123
    uaVersion.userAgent = "/dcrdtest:0.0.1/"
    uaVersionEncoded = baseVersionEncoded()[:-4]

    # lastBlockVersion is a version message that contains all fields
    # through the LastBlock field.
    lastBlockVersion = minimumMsgVersion()
    lastBlockVersion.addrMe = addrMe
    lastBlockVersion.nonce = 123123
    lastBlockVersion.userAgent = "/dcrdtest:0.0.1/"
    lastBlockVersion.lastBlock = 234234  # 0x392fa
    lastBlockVersionEncoded = baseVersionEncoded()

    tests = [
        (onlyRequiredVersion, onlyRequiredVersionEncoded),
        (addrMeVersion, addrMeVersionEncoded),
        (nonceVersion, nonceVersionEncoded),
        (uaVersion, uaVersionEncoded),
        (lastBlockVersion, lastBlockVersionEncoded),
    ]

    for expMsg, buf in tests:
        # Decode the message from wire format.
        msg = msgversion.MsgVersion.btcDecode(buf, wire.ProtocolVersion)
        assert sameMsgVersion(msg, expMsg)
