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
        addrMe,
        addrYou,
        nonce,
        lastBlock,
        services,
        disableRelayTx=False,
        protocolVersion=wire.ProtocolVersion,
        timestamp=None,
        userAgent=DefaultUserAgent,
    ):
        """
        Args:
            addrMe (NetAddress): Address of the local peer.
            addrYou (NetAddress): Address of the remote peer.
            nonce (int): Unique value associated with the  message that is used
                to detect self-connections.
            lastBlock (int): Last block seen by the generator of the version
                message.
            services (int): Bitfield which identifies the enabled services.
            disableRelayTx (bool): Optional. Default: False. Don't announce
                transactions to peer.
            protocolVersion (int): Optional. Default: wire.ProtocolVersion.
                Version of the protocol the node is using.
            timestamp (int): Optional. Default: current time. Time the message
                was generated. This is encoded as 8 bytes on the wire.
            userAgent (str): Optional. Default: DefaultUserAgent. The user agent
                that generated message.  This is encoded as a varString on the
                wire.  This has a max length of MaxUserAgentLen.
        """
        self.addrMe = addrMe
        self.addrYou = addrYou
        self.nonce = nonce
        self.lastBlock = lastBlock
        self.services = services
        self.disableRelayTx = disableRelayTx
        self.protocolVersion = protocolVersion
        self.timestamp = timestamp if timestamp is not None else int(time.time())
        self.userAgent = userAgent

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


def validateUserAgent(userAgent):
    """
    Check userAgent length against MaxUserAgentLen.

    Args:
        userAgent (string): The user agent string.
    """
    return len(userAgent) <= MaxUserAgentLen
