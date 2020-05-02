"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import time

from decred import DecredError
from decred.dcr.wire import netaddress, wire
from decred.util.encode import ByteArray


# MaxUserAgentLen is the maximum allowed length for the user agent field in a
# version message (MsgVersion).
MaxUserAgentLen = 256

# DefaultUserAgent for wire in the stack
DefaultUserAgent = "/tinywire:0.0.1/"

# Command string for the MsgVersion.
CmdVersion = "version"


class MsgVersion:
    """
    MsgVersion implements the Message API and represents a Decred version
    message.  It is used for a peer to advertise itself as soon as an outbound
    connection is made.  The remote peer then uses this information along with
    its own to negotiate.  The remote peer must then respond with a version
    message of its own containing the negotiated values followed by a verack
    message (MsgVerAck).  This exchange must take place before any further
    communication is allowed to proceed.
    """

    def __init__(
        self,
        protocolVersion,
        services,
        timestamp,
        addrYou,
        addrMe,
        nonce,
        userAgent,
        lastBlock,
        disableRelayTx,
    ):
        """
        Args:
            protocolVersion (int): Version of the protocol the node is using.
            services (int): Bitfield which identifies the enabled services.
            timestamp (int): Time the message was generated.  This is encoded as
                as 8 bytes on the wire.
            addrYou (NetAddress): Address of the remote peer.
            addrMe (NetAddress): Address of the local peer.
            nonce (int): Unique value associated with message that is used to
                detect self-connections.
            userAgent (str): The user agent that generated message.  This is
                encoded as a varString on the wire.  This has a max length of
                MaxUserAgentLen.
            lastBlock (int): Last block seen by the generator of the version
                message.
            disableRelayTx (bool): Don't announce transactions to peer.
        """
        self.protocolVersion = protocolVersion
        self.services = services
        self.timestamp = timestamp
        self.addrYou = addrYou
        self.addrMe = addrMe
        self.nonce = nonce
        self.userAgent = userAgent
        self.lastBlock = lastBlock
        self.disableRelayTx = disableRelayTx

    def hasService(self, service):
        """
        Whether the specified service is supported by the address.

        Args:
            service (int): Bitfield which identifies the service(s) to check.

        Returns:
            bool: True if this peer offers the service(s).
        """
        return self.services & service == service

    def addService(self, service):
        """
        Adds service(s) as a supported service.

        Args:
            service (int): Bitfield which identifies the service(s) to add.
        """
        self.services |= service

    @staticmethod
    def btcDecode(b, pver):
        """
        btcDecode decodes b using the Decred protocol encoding into the
        receiver. The version message is special in that the protocol version
        hasn't been negotiated yet.  As a result, the pver field is ignored and
        any fields which are added in new versions are optional.

        This is part of the Message API.

        Args:
            b (ByteArray): The encoded MsgVersion.
            pver (int): The protocol version. Unused.

        Returns:
            MsgVersion: The decoded MsgVersion.
        """
        uint64 = 8
        int32 = 4

        pver = b.pop(int32).unLittle().int()
        services = b.pop(uint64).unLittle().int()
        stamp = b.pop(uint64).unLittle().int()

        addrYou = netaddress.readNetAddress(b.pop(26), False)

        # Protocol versions >= 106 added a from address, nonce, and user agent
        # field and they are only considered present if there are bytes
        # remaining in the message.
        if len(b) > 0:
            addrMe = netaddress.readNetAddress(b.pop(26), False)
        else:
            addrMe = netaddress.NetAddress(
                ByteArray(length=16), port=0, services=0, stamp=0
            )

        nonce = 0
        if len(b) > 0:
            nonce = b.pop(uint64).unLittle().int()

        userAgent = ""
        if len(b) > 0:
            userAgent = wire.readVarString(b, pver)

            if not validateUserAgent(userAgent):
                raise DecredError(f"bad user agent: {userAgent}")

        # Protocol versions >= 209 added a last known block field.  It is only
        # considered present if there are bytes remaining in the message.
        lastBlock = 0
        if len(b) > 0:
            lastBlock = b.pop(int32).unLittle().int()

        # There was no relay transactions field before BIP0037Version, but
        # the default behavior prior to the addition of the field was to always
        # relay transactions.
        disableRelayTx = False
        if len(b) > 0:
            # The wire encoding for the field is true when transactions should
            # be relayed, so reverse it for the DisableRelayTx field.
            disableRelayTx = b.pop(1) == [0]

        return MsgVersion(
            protocolVersion=pver,
            services=services,
            timestamp=stamp,
            addrYou=addrYou,
            addrMe=addrMe,
            nonce=nonce,
            userAgent=userAgent,
            lastBlock=lastBlock,
            disableRelayTx=disableRelayTx,
        )

    def btcEncode(self, pver):
        """
        btcEncode encodes the receiver using the Decred protocol encoding.
        This is part of the Message API.

        Args:
            pver (int): The protocol version.

        Returns:
            ByteArray: The encoded MsgVersion.
        """
        if not validateUserAgent(self.userAgent):
            raise DecredError(f"bad user agent {self.userAgent}")

        b = ByteArray()
        b += ByteArray(self.protocolVersion, length=4).littleEndian()
        b += ByteArray(self.services, length=8).littleEndian()
        b += ByteArray(self.timestamp, length=8).littleEndian()
        b += netaddress.writeNetAddress(self.addrYou, False)
        b += netaddress.writeNetAddress(self.addrMe, False)
        b += ByteArray(self.nonce, length=8).littleEndian()
        b += wire.writeVarString(pver, self.userAgent)
        b += ByteArray(self.lastBlock, length=4).littleEndian()
        b += [0] if self.disableRelayTx else [1]

        return b

    def command(self):
        """
        The protocol command string for the message.  This is part of the
        Message API.

        Returns:
            str: The command string.
        """
        return CmdVersion

    def maxPayloadLength(self, pver):
        """
        The maximum length the payload can be for the receiver. This is part of
        the Message API.

        Args:
            pver (int): The protocol version. Unused.

        Returns:
            int: The maximum payload length.
        """
        # Protocol version 4 bytes + services 8 bytes + timestamp 8 bytes +
        # remote and local net addresses + nonce 8 bytes + length of user
        # agent (varInt) + max allowed useragent length + last block 4 bytes +
        # relay transactions flag 1 byte.
        return (
            33
            + (netaddress.MaxNetAddressPayload * 2)
            + wire.MaxVarIntPayload
            + MaxUserAgentLen
        )

    def addUserAgent(self, name, version, *comments):
        """
        Adds a user agent to the user agent string for the version message.  The
        version string is not defined to any strict format, although it is
        recommended to use the form "major.minor.revision" e.g. "2.6.41".

        Args:
            name (str): The agent name.
            version (str): The version string.
            *comments (str): Comments.
        """
        newUserAgent = f"{name}:{version}"

        if len(comments) != 0:
            s = "; ".join(comments)
            newUserAgent = f"{newUserAgent}({s})"

        newUserAgent = f"{self.userAgent}{newUserAgent}/"
        if not validateUserAgent(newUserAgent):
            raise DecredError(f"bad user agent {newUserAgent}")

        self.userAgent = newUserAgent


def newMsgVersion(addrMe, addrYou, nonce, lastBlock):
    """
    Decred version message that conforms to the Message API using the passed
    parameters and defaults for the remaining fields.

    Args:
        addrMe (NetAddress): Address of the local peer.
        addrYou (NetAddress): Address of the remote peer.
        nonce (int): Unique value associated with message that is used to detect
            self-connections.
        lastBlock (int): Last block seen by the generator of the version
            message.

    Returns:
        MsgVersion: The MsgVersion.
    """
    return MsgVersion(
        protocolVersion=wire.ProtocolVersion,
        services=0,
        timestamp=int(time.time()),
        addrYou=addrYou,
        addrMe=addrMe,
        nonce=nonce,
        userAgent=DefaultUserAgent,
        lastBlock=lastBlock,
        disableRelayTx=False,
    )


def newMsgVersionFromConn(conn, nonce, lastBlock):
    """
    Convenience function that extracts the remote and local address from conn
    and returns a new Decred version message that conforms to the Message
    interface. See newMsgVersion.

    Args:
        conn (NetConn): A connection object with localAddr and remoteAddr
            properties.
        nonce (int): Unique value associated with message that is used to detect
            self-connections.
        lastBlock (int): Last block seen by the generator of the version
            message.

    Returns:
        MsgVersion: The MsgVersion.
    """

    # Don't assume any services until we know otherwise.
    lna = netaddress.newNetAddress(conn.localAddr, 0)

    # Don't assume any services until we know otherwise.
    rna = netaddress.newNetAddress(conn.remoteAddr, 0)

    return newMsgVersion(lna, rna, nonce, lastBlock)


def validateUserAgent(userAgent):
    """
    Check userAgent length against MaxUserAgentLen.

    Args:
        userAgent (string): The user agent string.
    """
    if len(userAgent) > MaxUserAgentLen:
        return False
    return True
