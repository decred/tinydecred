"""
Copyright (c) 2020, The Decred developers
See LICENSE for details
"""

from blake256.blake256 import blake_hash
from nacl.hash import siphash24

from decred import DecredError
from decred.dcr.wire import wire
from decred.util.encode import ByteArray


# B is bits parameter for constructing GCS filters and results in the tunable
# parameter that is essentially used as the bin size in the underlying Golomb
# coding having a value of 2^B.
B = 19

# M is the inverse of the target false positive rate for constructing GCS
# filters.  This is the optimal value of M to minimize the size of the filter
# for B = 19.
M = 784931

# KeySize is the size of the byte array required for key material for the
# SipHash keyed hash function.
KeySize = 16


class SiphashEncoder:
    """
    PyNaCl's siphash 24 takes an encoder argument, which must have an encode
    method.
    """

    @staticmethod
    def encode(b):
        return ByteArray(b)


class EncodingError(DecredError):
    pass


class BitReader:
    """
    Read binary data as a bit stream.
    """

    def __init__(self, b):
        """
        Args:
            b (ByteArray): The binary data.
        """
        # Use a memoryview to prevent unnecessary copying.
        self.b = memoryview(b.b)
        self.next = 1 << 7

    def readUnary(self):
        """
        Returns the number of unread sequential one bits before the next zero
        bit. Raises EncodingError if no zero bits are encountered.

        Returns:
            int: The decoded unary number.
        """
        value = 0

        while True:
            b = self.b
            if len(b) == 0:
                raise EncodingError("no zero bit encountered")

            while self.next != 0:
                bit = b[0] & self.next
                self.next >>= 1
                if bit == 0:
                    return value
                value += 1

            self.b = b[1:]
            self.next = 1 << 7

    def readNBits(self, n):
        """
        Read n number of LSB bits of data from the bit stream in big endian
        format.

        Args:
            n (int): The number of bits to read.

        Returns:
            int: The bits interpreted as a big-endian integer.
        """
        if n > 64 or n < 0:
            raise DecredError(f"n > 64 or < 0 not allowed. given {n}")
        if n == 0:
            return 0

        if len(self.b) == 0:
            raise EncodingError("end of bytes")

        value = 0

        # If byte is partially read, read the rest.
        if self.next != 1 << 7:
            while n > 0:
                if self.next == 0:
                    self.next = 1 << 7
                    self.b = self.b[1:]
                    break
                n -= 1
                if self.b[0] & self.next != 0:
                    value |= 1 << n
                self.next >>= 1

        if n == 0:
            return value

        # Read 8 bits at a time.
        while n >= 8:
            if len(self.b) == 0:
                raise EncodingError("end of bytes")

            n -= 8
            value |= self.b[0] << n
            self.b = self.b[1:]

        if len(self.b) == 0:
            if n != 0:
                raise EncodingError("bytes exhausted")
            return value

        # Read the remaining bits.
        while n > 0:
            n -= 1
            if self.b[0] & self.next != 0:
                value |= 1 << n
            self.next >>= 1

        return value


class FilterV2:
    """
    A GCS filter for determining set membership with a 1/M false positive rate.
    """

    def __init__(self, n, filterData):
        """
        Args:
            n (int): The number of entries in the filter.
            filterData (ByteArray): The Rice-coded filter data.
        """
        self.n = n
        self.modulusNM = n * M
        self.filterData = filterData

    @staticmethod
    def deserialize(b):
        """
        Deserialize the filter.

        Args:
            b (ByteArray): The serialized filter.

        Returns:
            FilterV2: The filter.
        """
        filterData = ByteArray(b)
        n = 0
        if len(filterData) > 0:
            n = wire.readVarInt(filterData, 0)
        return FilterV2(n, filterData)

    def readFullUint64(self, bitReader):
        """
        Read a value represented by the sum of a unary multiple of the Golomb
        coding bin size (2^B) and a big-endian B-bit remainder.

        Args:
            b (BitReader): A BitReader.

        Returns:
            int: The integer.
        """
        v = bitReader.readUnary()
        rem = bitReader.readNBits(B)
        # Add the multiple and the remainder.
        return (v << B) + rem

    def match(self, key, data):
        """
        Check whether the bytes are likely (within collision probability) to be
        a member of the set represented by the filter.

        Args:
            key (ByteArray): The siphash key.
            data (ByteArray): The data to find.

        Returns:
            bool: Whether the data is likely to be in the set.
        """
        # An empty filter or empty data can't possibly match anything.
        if len(self.filterData) == 0 or len(data) == 0:
            return False
        if len(key) != 16:
            raise DecredError(f"key length {len(key)} != 16 not allowed")

        # Hash the search term with the same parameters as the filter.
        term = (
            siphash24(data.bytes(), key=key.bytes(), encoder=SiphashEncoder)
            .littleEndian()
            .int()
        )
        term = (term * self.modulusNM) >> 64

        # Go through the search filter and look for the desired value.
        bitStream = BitReader(self.filterData)
        lastValue = 0
        readInt = self.readFullUint64
        while lastValue <= term:
            # Read the difference between previous and new value from
            # bitstream.
            try:
                value = readInt(bitStream)
            except EncodingError:  # out of bytes
                return False

            # Add the previous value to it.
            value += lastValue
            if value == term:
                return True

            lastValue = value

        return False

    def matchAny(self, key, data):
        """
        Check whether any of the supplied data values are likely (within
        collision probability) to be a member of the set represented by the
        filter faster than calling match() for each value individually.

        Args:
            key (ByteArray): The siphash key.
            data list(ByteArray): The data to find.

        Returns:
            bool: Whether any member of the data is likely to be in the set.
        """
        # An empty filter or empty data can't possibly match anything.
        if len(self.filterData) == 0 or len(data) == 0:
            return False

        # Create an uncompressed filter of the search values.
        values = []
        mod = self.modulusNM
        keyB = key.bytes()
        for d in data:
            if len(d) == 0:
                continue
            v = (
                siphash24(d.bytes(), key=keyB, encoder=SiphashEncoder)
                .littleEndian()
                .int()
            )
            values.append((v * mod) >> 64)

        if len(values) == 0:
            return False

        values.sort()

        # Zip down the filters, comparing values until we either run out of
        # values to compare in one of the filters or we reach a matching value.
        bitStream = BitReader(self.filterData)
        searchSize = len(data)
        searchIdx = 0
        filterVal = 0

        readInt = self.readFullUint64
        for i in range(self.n):
            # Read the next item to compare from the filter.
            try:
                delta = readInt(bitStream)
            except EncodingError:  # out of bytes
                return False

            filterVal += delta

            again = False
            # Iterate through the values to search until either a match is found
            # or the search value exceeds the current filter value.
            while searchIdx < searchSize:
                searchVal = values[searchIdx]
                if searchVal == filterVal:
                    return True

                # Move to the next filter item once the current search value
                # exceeds it.
                if searchVal > filterVal:
                    again = True
                    break

                searchIdx += 1

            if again:
                continue
            # Exit early when there are no more values to search for.
            break

        return False

    def filterNData(self):
        """
        The filter data with the varint-encoded number of entries prepended.

        Returns:
            ByteArray: The data with count prepended.
        """
        return (
            wire.writeVarInt(0, self.n) if self.n else ByteArray()
        ) + self.filterData

    def hash(self):
        """
        Hash returns the BLAKE256 hash of the filter.

        Returns:
            ByteArray: The hash.
        """
        # Empty filters have a hash of all zeroes.
        nData = self.filterNData()
        if len(nData) == 0:
            return ByteArray(length=32)

        return ByteArray(blake_hash(nData.bytes()))
