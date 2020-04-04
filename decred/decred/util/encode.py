"""
Copyright (c) 2020, Brian Stafford
Copyright (c) 2020, the Decred developers
See LICENSE for details

A class that wraps ByteArray and provides some convenient operators.
"""

import struct

from decred import DecredError


NONE = "None".encode()


def filterNone(b):
    """
    If the provided argument is None, return the special None indicator bytes.
    Otherwise, the argument is returned directly.

    Args:
        b (bytes-like or None): The bytes to filter.

    Returns:
        bytes-like
    """
    if b is None:
        return NONE
    return b


def extractNone(b):
    """
    If the provided bytes are the special None indicator, return None, else
    return the bytes.

    Args:
        b (bytes-like): The bytes to filter.

    Returns:
        (bytes-like or None)
    """
    if b == NONE:
        return None
    return b


def intToBytes(i, signed=False):
    """
    Encodes an integer to bytes.

    Args:
        i (int): The integer.
        signed (bool): Whether to encode as a signed integer.

    Returns:
        bytearray: The encoded integer.
    """
    length = ((i + ((i * signed) < 0)).bit_length() + 7 + signed) // 8
    return bytearray(i.to_bytes(length, byteorder="big", signed=signed))


def intFromBytes(b, signed=False):
    """
    Decodes an integer from bytes.

    Args:
        b (bytes-like): The encoded integer.
        signed (bool): Whether to decode as a signed integer.

    Returns:
        int: The decoded integer.
    """
    return int.from_bytes(b, "big", signed=signed)


def floatToBytes(flt):
    """
    Encodes a float to bytes.

    Args:
        flt (float): The float to encode.

    Returns:
        bytearray: The encoded float.
    """
    return bytearray(struct.pack("d", flt))


def floatFromBytes(b):
    """
    Decode a float from bytes.

    Args:
        b (bytes-like): The float bytes to decode.

    Returns:
        float: The decoded float.
    """
    return struct.unpack("d", b)[0]


def boolToBytes(v):
    """
    Encode the boolean value as a byte.

    Args:
        v (bool): A boolean to encode.

    Returns:
        int: A byte.
    """
    return 0x01 if v else 0x00


def boolFromBytes(b):
    """
    Decode the byte as True if 0x01, else False.

    Args:
        b (bytes-like): A length-1 byte buffer with the encoded boolean.

    Returns:
        bool: The decoded value.
    """
    return b == 0x01


def decodeBA(b, copy=False):
    """
    Decode into a bytearray.

    Args:
        b (str, bytes-like, ByteArray, int, list(int)): The value to decode to
            a bytearray. Strings are interpreted as hexadecimal. Integers are
            minimally encoded to an unsigned integer.

    Returns:
        bytearray: The decoded bytes.
    """
    if isinstance(b, ByteArray):
        return bytearray(b.b) if copy else b.b
    if isinstance(b, bytearray):
        return bytearray(b) if copy else b
    if isinstance(b, bytes):
        return bytearray(b)
    if isinstance(b, int):
        return intToBytes(b) if b else bytearray([0])
    if isinstance(b, str):
        return bytearray.fromhex(b)
    if hasattr(b, "__iter__"):
        return bytearray(b)
    raise TypeError("decodeBA: unknown type %s" % type(b))


class ByteArray:
    """
    ByteArray is a bytearray manager. It implements a subset of bytearray's
    bitwise operators and provides some convenience decodings on the fly, so
    operations work with various types of input.  Since bytearrays are mutable,
    ByteArray can also zero the internal value without relying on garbage
    collection. An important difference between ByteArray and bytearray is that
    an integer argument to ByteArray constructor will result in the shortest
    possible byte representation of the integer, where for bytearray an int
    argument results in a zero-valued bytearray of said length. To get a
    zero-valued or zero-padded ByteArray of length n, use the `length` keyword
    argument.
    """

    def __init__(self, b=b"", copy=True, length=None):
        """
        Set copy to False if you want to share the memory with another
        bytearray/ByteArray. If the type of b is not bytearray or ByteArray,
        copy has no effect.
        """
        if length:
            self.b = decodeBA(ByteArray(bytearray(length)) | b, copy=False)
        else:
            self.b = decodeBA(b, copy=copy)

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        return ByteArray(b)

    @staticmethod
    def blob(ba):
        """Satisfies the encode.Blobber API"""
        return ba.b

    def comp(self, a):
        """
        comp gets the underlying bytearray and length of both this ByteArray
        and a.

        Args:
            a (ByteArray): The other ByteArray.

        Returns:
            bytearray: This ByteArray's bytearray.
            int: This ByteArray's length.
            bytearray: The other ByteArray's bytearray.
            int: The other ByteArray's length.
        """
        a = decodeBA(a)
        aLen, bLen = len(a), len(self.b)
        if aLen > bLen:
            raise DecredError("decode: invalid length %i > %i" % (aLen, bLen))
        return a, aLen, self.b, bLen

    def __lt__(self, a):
        return bytearray.__lt__(self.b, decodeBA(a))

    def __le__(self, a):
        return bytearray.__le__(self.b, decodeBA(a))

    def __eq__(self, a):
        try:
            return bytearray.__eq__(self.b, decodeBA(a))
        except Exception:
            return False

    def __ne__(self, a):
        try:
            return bytearray.__ne__(self.b, decodeBA(a))
        except Exception:
            return True

    def __ge__(self, a):
        return bytearray.__ge__(self.b, decodeBA(a))

    def __gt__(self, a):
        return bytearray.__gt__(self.b, decodeBA(a))

    def __repr__(self):
        return "ByteArray(" + self.hex() + ")"

    def __len__(self):
        return len(self.b)

    def __and__(self, a):
        a, aLen, b, bLen = self.comp(a)
        b = ByteArray(b)
        for i in range(bLen):
            b[bLen - i - 1] &= a[aLen - i - 1] if i < aLen else 0
        return b

    def __iand__(self, a):
        a, aLen, b, bLen = self.comp(a)
        for i in range(bLen):
            b[bLen - i - 1] &= a[aLen - i - 1] if i < aLen else 0
        return self

    def __or__(self, a):
        a, aLen, b, bLen = self.comp(a)
        b = ByteArray(b)
        for i in range(bLen):
            b[bLen - i - 1] |= a[aLen - i - 1] if i < aLen else 0
        return b

    def __ior__(self, a):
        a, aLen, b, bLen = self.comp(a)
        for i in range(bLen):
            b[bLen - i - 1] |= a[aLen - i - 1] if i < aLen else 0
        return self

    def __add__(self, a):
        return self.__iadd__(a)

    def __iadd__(self, a):
        """append the bytes and return a new ByteArray"""
        a = decodeBA(a)
        return ByteArray(self.b + a)

    def __getitem__(self, k):
        if isinstance(k, slice):
            return ByteArray(self.b[k.start : k.stop : k.step], copy=False)
        return self.b[k]

    def __setitem__(self, i, v):
        v = decodeBA(v, copy=False)
        if i + len(v) > len(self.b):
            raise DecredError("source bytes too long")
        for j in range(len(v)):
            self.b[i + j] = v[j]

    def __reversed__(self):
        return ByteArray(bytearray(reversed(self.b)))

    def __hash__(self):
        """Enables ByteArray to be a dict key."""
        return hash(bytes(self.b))

    def hex(self):
        """
        A hexadecimal string representation of the bytes.

        Returns:
            str: The hex bytes.
        """
        return self.b.hex()

    def rhex(self):
        """
        A reversed hexadecimal string representation of the bytes.

        Returns:
            str: The hex bytes.
        """
        return self.__reversed__().hex()

    def zero(self):
        """
        Sets the bytes of the underlying bytearray to zero. The benefit of
        zeroing is that the info is destroyed immediately, rather than relying
        on the garbage collector.
        """
        for i in range(len(self.b)):
            self.b[i] = 0

    def iszero(self):
        """
        True if all bytes are zero.
        """
        return all((v == 0 for v in self.b))

    def iseven(self):
        """
        True if empty or if last byte is zero.
        """
        l = len(self.b)
        return l == 0 or self.b[l - 1] == 0

    def int(self):
        """The bytes as an integer."""
        return intFromBytes(self.b)

    def bytes(self):
        """The bytes as Python `bytes`."""
        return bytes(self.b)

    def unLittle(self):
        """A copy of the ByteArray, reversed."""
        return self.littleEndian()

    def littleEndian(self):
        """A copy of the ByteArray, reversed."""
        return ByteArray(reversed(self.b))

    def copy(self):
        """A copy of the ByteArray."""
        return ByteArray(self.b)

    def pop(self, n):
        """
        Remove n bytes from the beginning of the ByteArray, returning the bytes.
        """
        b = self[:n]
        self.b = self.b[n:]
        return b


def rba(*a, **k):
    """
    Reversed ByteArray. All args and kwargs are passed to the ByteArray
    constructor.
    """
    return reversed(ByteArray(*a, **k))


class BuildyBytes(ByteArray):
    """
    The BuildyBytes class is used to construct (optionally versioned) linearly-
    encoded 2-D byte arrays.
    """

    def __init__(self, version=None):
        """
        Constructor for a BuildyBytes.

        Args:
            version (int): optinonal. The version to encode. Default encodes no
                version byte.
        """
        if version == 0:
            version = [0x00]
        if version is None:
            version = []
        super().__init__(version)

    def addData(self, d):
        """
        addData adds the data to the BuildyBytes. self is returned to enable
        chaining. The data has hard-coded length limit of uint16_max = 65535
        bytes.
        """
        d = decodeBA(d)
        lenBytes = intToBytes(len(d))
        bLen = len(lenBytes)
        if bLen > 2:
            raise DecredError("cannot push data longer than 65535")
        if bLen == 2:
            lBytes = bytearray((0xFF, lenBytes[0], lenBytes[1]))
        elif bLen == 1:
            lBytes = lenBytes
        elif bLen == 0:
            lBytes = bytearray((0x00,))
        self.b += lBytes + d
        return self


def extractPushes(b):
    """
    Parses the linearly-encoded 2D byte array into a list of byte arrays.

    Args:
        b (bytes-like): The linearly encoded 2-D byte array.

    Returns:
        list(bytes-like): The 2-D byte array.
    """
    pushes = []
    while True:
        if len(b) == 0:
            break
        bLen = b[0]
        b = b[1:]
        if bLen == 255:
            if len(b) < 2:
                raise DecredError("2 bytes not available for uint16 data length")
            bLen = intFromBytes(b[:2])
            b = b[2:]
        if len(b) < bLen:
            raise DecredError("data too short for pop of %d bytes" % bLen)
        pushes.append(b[:bLen])
        b = b[bLen:]
    return pushes


def decodeBlob(b):
    """
    decodeBlob decodes a versioned blob into its version and the pushes extracted
    from its data.

    Args:
        b (bytes-like): The bytes to decode.

    Returns:
        int: The blob version (the version passed to BuildyBytes).
        list(bytes-like): The data pushes.
    """
    if len(b) == 0:
        raise DecredError("zero length blob not allowed")
    return b[0], extractPushes(b[1:])


def unblobStrList(b):
    """
    Decode a list of strings from the bytes.

    Args:
        bytes-like: The encoded list.

    Returns:
        list(str): The decoded list.
    """
    return [s.decode("utf-8") for s in extractPushes(b)]


def blobStrList(strs):
    """
    Encode a list of strings a bytes.

    Args:
        list(str): The strings to encode.

    Returns:
        bytearray: The encoded list.
    """
    b = BuildyBytes()
    for s in strs:
        b.addData(s.encode("utf-8"))
    return b.b


def unblobCheck(class_name, version, pushes, check_data):
    """
    Check version and pushes to unblob.

    Args:
        class_name str: the class name that will appear in error messages.
        version int: the version number that will be checked.
        pushes int: the number of pushes that will be checked.
        check_data dict: keys are version numbers, values are number of
            expected pushes.

    Raises:
        NotImplementedError if version is not in check_data keys.
        DecredError if pushes is not the value in check_data keyed by version.
    """
    if version not in check_data.keys():
        raise NotImplementedError(f"{class_name}: unsupported version {version}")
    expected_pushes = check_data[version]
    if pushes != expected_pushes:
        raise DecredError(
            f"{class_name}: expected {expected_pushes} pushes, got {pushes}"
        )
