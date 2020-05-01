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

    def __init__(self, ip, port, services, stamp):
        """
		Args:
			ip (str or bytes-like): The peer's IP address.
			port (int): The peer's port.
			services (int): Bitfield which identifies the services supported by
				the peer.
			stamp (int): The last time the peer was seen.
		"""
        # Last time the address was seen.  This is, unfortunately, encoded as an
        # int on the wire and therefore is limited to 2106.  This field is
        # not present in the Decred version message (MsgVersion) nor was it
        # added until protocol version >= NetAddressTimeVersion.
        self.timestamp = stamp

        self.services = services

        # If the IP is a string, parse it to bytes.
        if isinstance(ip, str):
            ip = decodeStringIP(ip)
        self.ip = ip

        # Port the peer is using.  This is encoded in big endian on the wire
        # which differs from most everything else.
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


def newNetAddressIPPort(ip, port, services):
    """
	A new NetAddress using the provided IP, port, and supported services with
	defaults for the remaining fields.

	Args:
		ip (str or bytes-like): The peer's IP address.
		port (int): The peer's port.
		services (int): Bitfield which identifies the services supported by
			the peer.

	Returns:
		NetAddress: The peer's NetAddress.
	"""
    return newNetAddressTimestamp(int(time.time()), services, ip, port)


def newNetAddressTimestamp(stamp, services, ip, port):
    """
	A new NetAddress using the provided timestamp, IP, port, and supported
	services.

	Args:
		stamp (int): The last time the peer was seen.
		ip (str or bytes-like): The peer's IP address.
		port (int): The peer's port.
		services (int): Bitfield which identifies the services supported by
			the peer.

	Returns:
		NetAddress: The peer's NetAddress.
	"""
    # Limit the timestamp to one second precision since the protocol
    # doesn't support better.
    return NetAddress(ip, port, services, stamp)


def newNetAddress(tcpAddr, services):
    """
	A new NetAddress using the provided TCPAddr and supported services with
	defaults for the remaining fields.

	Args:
		tcpAddr (TCPAddr): The peer's address.
		services (int): Bitfield which identifies the services supported by
			the peer.

	Returns:
		NetAddress: The peer's NetAddress.
	"""
    return newNetAddressIPPort(tcpAddr.ip, tcpAddr.port, services)


def readNetAddress(b, ts):
    """
	Reads an encoded NetAddress from b depending on the protocol version and
	whether or not the timestamp is included per ts.  Some messages like version do
	not include the timestamp.

	Args:
		b (ByteArray): The encoded NetAddress.
		ts (bool): Whether or not the NetAddress has a timestamp.

	Returns:
		NetAddress: The decoded NetAddress.
	"""
    expLen = 30 if ts else 26
    if len(b) != expLen:
        raise DecredError(
            f"readNetAddress wrong length (ts={ts}) expected {expLen}, got {len(b)}"
        )

    # NOTE: The Decred protocol uses a uint32 for the timestamp so it will
    # stop working somewhere around 2106.  Also timestamp wasn't added until
    # protocol version >= NetAddressTimeVersion
    stamp = b.pop(4).unLittle().int() if ts else 0
    services = b.pop(8).unLittle().int()
    ip = b.pop(16)
    if ip[:12] == ipv4to16prefix:
        ip = ip[12:]

    # Sigh.  Decred protocol mixes little and big endian.
    port = b.pop(2).int()

    return NetAddress(ip=ip, port=port, services=services, stamp=stamp,)


def writeNetAddress(netAddr, ts):
    """
	writeNetAddress serializes a NetAddress depending on the protocol
	version and whether or not the timestamp is included per ts.  Some messages
	like version do not include the timestamp.

	Args:
		netAddr (NetAddress): The peer's NetAddress.
		ts (bool): Whether to encode the timestamp.

	Returns:
		ByteArray: The encoded NetAddress.
	"""
    # NOTE: The Decred protocol uses a uint32 for the timestamp so it will
    # stop working somewhere around 2106.  Also timestamp wasn't added until
    # until protocol version >= NetAddressTimeVersion.
    b = ByteArray(netAddr.timestamp, length=4).littleEndian() if ts else ByteArray()

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


class TCPAddr:
    """ TCPAddr is a mimic of Go's net.TCPAddr. """

    def __init__(self, ip, port, zone=None):
        """
		Args:
			ip (str or bytes-like): The IP.
			port (int): The port.
			zone (str): The IPv6 scoped addressing zone.
		"""
        if isinstance(ip, str):
            ip = decodeStringIP(ip)
        self.ip = ip
        self.port = port
        self.zone = zone


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
        return socket.inet_pton(socket.AF_INET6, ip)
