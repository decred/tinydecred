"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import socket
import time

from decred import DecredError
from decred.util.encode import ByteArray


MaxNetAddressPayload = 30

# Prefix for a IPv4 adderess encoded as 16 bytes.
ipv4to16prefix = ByteArray(0xFFFF, length=12)


class NetAddress:
    """
    NetAddress defines information about a peer on the network including the time
    it was last seen, the services it supports, its IP address, and port.
    """

    def __init__(self, ip, port, services, stamp=None):
        """
        Args:
            ip (str or bytes-like): The peer's IP address.
            port (int): Port the peer is using.  This is encoded in big endian
                on the wire which differs from most everything else.
            services (int): Bitfield which identifies the services supported by
                the peer.
            stamp (int): Optional. Default: current time. The last time the peer
                was seen. This is, unfortunately, encoded as an int on the wire
                and therefore is limited to 2106. This field is not present in
                the Decred version message (MsgVersion) nor was it added until
                protocol version >= NetAddressTimeVersion.
        """
        self.timestamp = stamp if stamp else int(time.time())
        self.services = services

        # If the IP is a string, parse it to bytes.
        if isinstance(ip, str):
            ip = decodeStringIP(ip)
        self.ip = ip

        self.port = port

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


def readNetAddress(b, hasStamp):
    """
    Reads an encoded NetAddress from b depending on the protocol version and
    whether or not the timestamp is included per hasStamp.  Some messages like
    version do not include the timestamp.

    Args:
        b (ByteArray): The encoded NetAddress.
        hasStamp (bool): Whether or not the NetAddress has a timestamp.

    Returns:
        NetAddress: The decoded NetAddress.
    """
    expLen = 30 if hasStamp else 26
    if len(b) != expLen:
        raise DecredError(
            f"readNetAddress wrong length (hasStamp={hasStamp}) expected {expLen}, got {len(b)}"
        )

    # NOTE: The Decred protocol uses a uint32 for the timestamp so it will
    # stop working somewhere around 2106.  Also timestamp wasn't added until
    # protocol version >= NetAddressTimeVersion
    stamp = b.pop(4).unLittle().int() if hasStamp else 0
    services = b.pop(8).unLittle().int()
    ip = b.pop(16)
    if ip[:12] == ipv4to16prefix:
        ip = ip[12:]

    # Sigh.  Decred protocol mixes little and big endian.
    port = b.pop(2).int()

    return NetAddress(ip=ip, port=port, services=services, stamp=stamp,)


def writeNetAddress(netAddr, hasStamp):
    """
    writeNetAddress serializes a NetAddress depending on the protocol
    version and whether or not the timestamp is included per hasStamp.  Some
    messages like version do not include the timestamp.

    Args:
        netAddr (NetAddress): The peer's NetAddress.
        hasStamp (bool): Whether to encode the timestamp.

    Returns:
        ByteArray: The encoded NetAddress.
    """
    # NOTE: The Decred protocol uses a uint32 for the timestamp so it will
    # stop working somewhere around 2106.  Also timestamp wasn't added until
    # until protocol version >= NetAddressTimeVersion.
    b = (
        ByteArray(netAddr.timestamp, length=4).littleEndian()
        if hasStamp
        else ByteArray()
    )

    # Ensure to always write 16 bytes even if the ip is nil.
    ip = netAddr.ip
    if ip is None:
        ip = ByteArray(length=16)
    if len(ip) == 4:
        ip = ipv4to16prefix + ip

    b += ByteArray(netAddr.services, length=8).littleEndian()
    b += ByteArray(ip, length=16)
    b += ByteArray(netAddr.port, length=2)

    return b


def decodeStringIP(ip):
    """
    Parse an IP string to bytes.

    Args:
        ip (str): The string-encoded IP address.

    Returns:
        bytes-like: The byte-encoded IP address.
    """
    try:
        return socket.inet_pton(socket.AF_INET, ip)
    except OSError:
        pass
    try:
        return socket.inet_pton(socket.AF_INET6, ip)
    except OSError:
        raise DecredError(f"failed to decode IP {ip}")
