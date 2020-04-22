"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details
"""

from base64 import b64decode
from zlib import decompress as zdecompress

from decred.util.encode import ByteArray

from .bytepoints import secp256k1BytePoints


# Constants used to make the code more readable.
twoBitsMask = 0x03
fourBitsMask = 0x0F
sixBitsMask = 0x3F
eightBitsMask = 0xFF

# Constants related to the field representation.

# fieldWords is the number of words used to internally represent the
# 256-bit value.
fieldWords = 10

# fieldBase is the exponent used to form the numeric base of each word.
# 2^(fieldBase*i) where i is the word position.
fieldBase = 26

# fieldBaseMask is the mask for the bits in each word needed to
# represent the numeric base of each word (except the most significant
# word).
fieldBaseMask = (1 << fieldBase) - 1

# fieldMSBBits is the number of bits in the most significant word used
# to represent the value.
fieldMSBBits = 256 - (fieldBase * (fieldWords - 1))

# fieldMSBMask is the mask for the bits in the most significant word
# needed to represent the value.
fieldMSBMask = (1 << fieldMSBBits) - 1

# fieldPrimeWordZero is word zero of the secp256k1 prime in the
# internal field representation.  It is used during negation.
fieldPrimeWordZero = 0x3FFFC2F

# fieldPrimeWordOne is word one of the secp256k1 prime in the
# internal field representation.  It is used during negation.
fieldPrimeWordOne = 0x3FFFFBF

# The secp256k1 prime is equivalent to 2^256 - 4294968273.
# 4294968273 in field representation (base 2^26) is:
# n[0] = 977
# n[1] = 64
# That is to say (2^26 * 64) + 977 = 4294968273
# Since each word is in base 26, the upper terms (t10 and up) start
# at 260 bits (versus the final desired range of 256 bits), so the
# field representation of 'c' from above needs to be adjusted for the
# extra 4 bits by multiplying it by 2^4 = 16.  4294968273 * 16 =
# 68719492368.  Thus, the adjusted field representation of 'c' is:
# n[0] = 977 * 16 = 15632
# n[1] = 64 * 16 = 1024
# That is to say (2^26 * 1024) + 15632 = 68719492368
primePartBy16 = 68719492368


class FieldVal:
    """
    WARNING: Since it is so important for the field arithmetic to be extremely
    fast for high performance crypto, this type does not perform any validation
    of documented preconditions where it ordinarily would.  As a result, it is
    IMPERATIVE for callers to understand some key concepts that are described
    below and ensure the methods are called with the necessary preconditions that
    each method is documented with.  For example, some methods only give the
    correct result if the field value is normalized and others require the field
    values involved to have a maximum magnitude and THERE ARE NO EXPLICIT CHECKS
    TO ENSURE THOSE PRECONDITIONS ARE SATISFIED.  This does, unfortunately, make
    the type more difficult to use correctly and while I typically prefer to
    ensure all state and input is valid for most code, this is a bit of an
    exception because those extra checks really add up in what ends up being
    critical hot paths.

    The first key concept when working with this type is normalization.  In order
    to avoid the need to propagate a ton of carries, the internal representation
    provides additional overflow bits for each word of the overall 256-bit value.
    This means that there are multiple internal representations for the same
    value and, as a result, any methods that rely on comparison of the value,
    such as equality and oddness determination, require the caller to provide a
    normalized value.

    The second key concept when working with this type is magnitude.  As
    previously mentioned, the internal representation provides additional
    overflow bits which means that the more math operations that are performed on
    the field value between normalizations, the more those overflow bits
    accumulate.  The magnitude is effectively that maximum possible number of
    those overflow bits that could possibly be required as a result of a given
    operation.  Since there are only a limited number of overflow bits available,
    this implies that the max possible magnitude MUST be tracked by the caller
    and the caller MUST normalize the field value if a given operation would
    cause the magnitude of the result to exceed the max allowed value.

    IMPORTANT: The max allowed magnitude of a field value is 64.

    FieldVal implements optimized fixed-precision arithmetic over the
    secp256k1 finite field.  This means all arithmetic is performed modulo
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f.  Each
    256-bit value is represented as 10 32-bit integers in base 2^26.  This
    provides 6 bits of overflow in each word (10 bits in the most significant
    word) for a total of 64 bits of overflow (9*6 + 10 = 64).  It only
    implements the arithmetic needed for elliptic curve operations.

    The following depicts the internal representation:
         -----------------------------------------------------------------
        |        n[9]       |        n[8]       | ... |        n[0]       |
        | 32 bits available | 32 bits available | ... | 32 bits available |
        | 22 bits for value | 26 bits for value | ... | 26 bits for value |
        | 10 bits overflow  |  6 bits overflow  | ... |  6 bits overflow  |
        | Mult: 2^(26*9)    | Mult: 2^(26*8)    | ... | Mult: 2^(26*0)    |
         -----------------------------------------------------------------

    For example, consider the number 2^49 + 1.  It would be represented as:
        n[0] = 1
        n[1] = 2^23
        n[2..9] = 0

    The full 256-bit value is then calculated by looping i from 9..0 and
    doing sum(n[i] * 2^(26i)) like so:
        n[9] * 2^(26*9) = 0    * 2^234 = 0
        n[8] * 2^(26*8) = 0    * 2^208 = 0
        ...
        n[1] * 2^(26*1) = 2^23 * 2^26  = 2^49
        n[0] * 2^(26*0) = 1    * 2^0   = 1
        Sum: 0 + 0 + ... + 2^49 + 1 = 2^49 + 1
    """

    def __init__(self):
        """
        Set the newly created field value to zero.
        """
        self.zero()

    def zero(self):
        """
        zero sets the field value to zero.  A newly created field value is
        already set to zero.  This function can be useful to clear an existing
        field value for reuse.

        Preconditions: None
        Output Normalized: Yes
        Output Max Magnitude: 1
        """
        self.n = [0] * 10

    @staticmethod
    def fromHex(hexString):
        """
        fromHex decodes the passed big-endian hex string into the internal
        field value representation.  Only the first 32-bytes are used.

        The field value is returned to support chaining, enabling syntax like:
            f = FieldVal.fromHex("abc").add(1)
        so that:
            f = 0xabc + 1

        Args:
            hexString (str): the hex string to be used as field value.
        Return:
            FieldVal: the created object.
        """
        if len(hexString) % 2 != 0:
            hexString = "0" + hexString
        b = ByteArray(hexString)
        f = FieldVal()
        f.setBytes(b)
        return f

    @staticmethod
    def fromInt(i):
        """
        fromInt sets the passed integer into the internal field value
        representation.

        The field value is returned to support chaining, enabling syntax like:
            f = FieldVal.fromInt(2).mul(3)
        so that:
            f = 2 * 3

        Args:
            i (int): the integer to be used as field value.
        Return:
            FieldVal: the created object.
        """
        f = FieldVal()
        return f.setInt(i)

    def setInt(self, i):
        """
        setInt sets the field value to the passed integer.  This is a
        convenience function since it is fairly common to perform some
        arithmetic with small native integers.

        The field value is returned to support chaining, enabling syntax like:
            f = FieldVal().setInt(2).mul(f2)
        so that:
            f = 2 * f2

        Preconditions: None
        Output Normalized: Yes
        Output Max Magnitude: 1

        Args:
            i (int): the integer value to be set as the field value.

        Return:
            FieldVal: the object itself.
        """
        self.zero()
        self.n[0] = i
        return self

    def equals(self, f):
        """
        Equals returns whether or not the two field values are the same.

        Preconditions:
          - Both field values being compared MUST be normalized.

        Args:
            f (FieldVal): the field value to be compared.

        Return:
            bool: True if the two field values are the same, False otherwise.
        """
        return all((x == y for x, y in zip(f.n, self.n)))

    def setBytes(self, b):
        """
        setBytes packs the passed 32-byte big-endian value into the internal
        field value representation.

        Preconditions: None
        Output Normalized: Yes if no overflow, no otherwise
        Output Max Magnitude: 1

        Args:
            b (bytes-like): the bytearray value to be set as the field value.
        """
        b = ByteArray(b, length=32, copy=False)
        self.n[0] = b[31] | b[30] << 8 | b[29] << 16 | (b[28] & twoBitsMask) << 24
        self.n[1] = b[28] >> 2 | b[27] << 6 | b[26] << 14 | (b[25] & fourBitsMask) << 22
        self.n[2] = b[25] >> 4 | b[24] << 4 | b[23] << 12 | (b[22] & sixBitsMask) << 20
        self.n[3] = b[22] >> 6 | b[21] << 2 | b[20] << 10 | b[19] << 18
        self.n[4] = b[18] | b[17] << 8 | b[16] << 16 | (b[15] & twoBitsMask) << 24
        self.n[5] = b[15] >> 2 | b[14] << 6 | b[13] << 14 | (b[12] & fourBitsMask) << 22
        self.n[6] = b[12] >> 4 | b[11] << 4 | b[10] << 12 | (b[9] & sixBitsMask) << 20
        self.n[7] = b[9] >> 6 | b[8] << 2 | b[7] << 10 | b[6] << 18
        self.n[8] = b[5] | b[4] << 8 | b[3] << 16 | (b[2] & twoBitsMask) << 24
        self.n[9] = b[2] >> 2 | b[1] << 6 | b[0] << 14

    def isZero(self):
        """
        isZero returns whether or not the field value is equal to zero in
        constant time.

        Preconditions:
        - The field value MUST be normalized.

        Return:
            bool: True if the field value is zero, False otherwise.
        """
        return all((x == 0 for x in self.n))

    def set(self, f):
        """
        set sets the field value equal to the passed value.  The normalization
        and magnitude of the two fields will be identical.

        The field value is returned to support chaining, enabling syntax like:
            f = FieldVal().set(f2).add(1)
        so that:
            f = f2 + 1
        where f2 is not modified.

        Preconditions: None
        Output Normalized: Same as input value
        Output Max Magnitude: Same as input value

        Args:
            f (FieldVal): the field value to be copied.

        Return:
            FieldVal: the object itself.
        """
        self.n = [x for x in f.n]
        return self

    def normalize(self):
        """
        Normalize normalizes the internal field words into the desired range and
        performs fast modular reduction over the secp256k1 prime by making use
        of the special form of the prime.

        Preconditions: None
        Output Normalized: Yes
        Output Max Magnitude: 1

        Return:
            FieldVal: the object itself.
        """
        # The field representation leaves 6 bits of overflow in each word, so
        # intermediate calculations can be performed without needing to
        # propagate the carry to each higher word.  In order to normalize, we
        # need to "compact" the full 256-bit value to the right while
        # propagating any carries through to the high order word.
        #   Since this field is doing arithmetic modulo the secp256k1 prime, we
        # also need to perform modular reduction over the prime.
        #   Per [HAC] section 14.3.4: Reduction method of moduli of special form,
        # when the modulus is of the special form m = b^t - c, highly efficient
        # reduction can be achieved.
        #   The secp256k1 prime is equivalent to 2^256 - 4294968273, so it fits
        # this criteria.
        #   4294968273 in field representation (base 2^26) is:
        # n[0] = 977
        # n[1] = 64
        #   That is to say (2^26 * 64) + 977 = 4294968273
        #   The algorithm presented in the referenced section typically repeats
        # until the quotient is zero.  However, due to our field representation
        # we already know to within one reduction how many times we would need
        # to repeat as it's the uppermost bits of the high order word.  Thus we
        # can simply multiply the magnitude by the field representation of the
        # prime and do a single iteration.  After this step there might be an
        # additional carry to bit 256 (bit 22 of the high order word).
        f = self
        t9 = f.n[9]
        m = t9 >> fieldMSBBits
        t9 = t9 & fieldMSBMask
        t0 = f.n[0] + m * 977
        t1 = (t0 >> fieldBase) + f.n[1] + (m << 6)
        t0 = t0 & fieldBaseMask
        t2 = (t1 >> fieldBase) + f.n[2]
        t1 = t1 & fieldBaseMask
        t3 = (t2 >> fieldBase) + f.n[3]
        t2 = t2 & fieldBaseMask
        t4 = (t3 >> fieldBase) + f.n[4]
        t3 = t3 & fieldBaseMask
        t5 = (t4 >> fieldBase) + f.n[5]
        t4 = t4 & fieldBaseMask
        t6 = (t5 >> fieldBase) + f.n[6]
        t5 = t5 & fieldBaseMask
        t7 = (t6 >> fieldBase) + f.n[7]
        t6 = t6 & fieldBaseMask
        t8 = (t7 >> fieldBase) + f.n[8]
        t7 = t7 & fieldBaseMask
        t9 = (t8 >> fieldBase) + t9
        t8 = t8 & fieldBaseMask

        # At this point, the magnitude is guaranteed to be one; however, the
        # value could still be greater than the prime if there was either a
        # carry through to bit 256 (bit 22 of the higher order word) or the
        # value is greater than or equal to the field characteristic.  The
        # following determines if either of these conditions is true and does
        # the final reduction in constant time.
        #
        # Note that the if/else statements here intentionally do the bitwise
        # operators even when it won't change the value to ensure constant time
        # between the branches.  Also note that 'm' will be zero when neither
        # of the aforementioned conditions is true, and the value will not be
        # changed when 'm' is zero.
        m = 1
        if t9 == fieldMSBMask:
            m &= 1
        else:
            m &= 0
        if t2 & t3 & t4 & t5 & t6 & t7 & t8 == fieldBaseMask:
            m &= 1
        else:
            m &= 0
        if (((t0 + 977) >> fieldBase) + t1 + 64) > fieldBaseMask:
            m &= 1
        else:
            m &= 0
        if t9 >> fieldMSBBits != 0:
            m |= 1
        else:
            m |= 0
        t0 = t0 + m * 977
        t1 = (t0 >> fieldBase) + t1 + (m << 6)
        t0 = t0 & fieldBaseMask
        t2 = (t1 >> fieldBase) + t2
        t1 = t1 & fieldBaseMask
        t3 = (t2 >> fieldBase) + t3
        t2 = t2 & fieldBaseMask
        t4 = (t3 >> fieldBase) + t4
        t3 = t3 & fieldBaseMask
        t5 = (t4 >> fieldBase) + t5
        t4 = t4 & fieldBaseMask
        t6 = (t5 >> fieldBase) + t6
        t5 = t5 & fieldBaseMask
        t7 = (t6 >> fieldBase) + t7
        t6 = t6 & fieldBaseMask
        t8 = (t7 >> fieldBase) + t8
        t7 = t7 & fieldBaseMask
        t9 = (t8 >> fieldBase) + t9
        t8 = t8 & fieldBaseMask
        t9 = t9 & fieldMSBMask  # Remove potential multiple of 2^256.

        # Finally, set the normalized and reduced words.
        f.n[0] = t0
        f.n[1] = t1
        f.n[2] = t2
        f.n[3] = t3
        f.n[4] = t4
        f.n[5] = t5
        f.n[6] = t6
        f.n[7] = t7
        f.n[8] = t8
        f.n[9] = t9
        return f

    def negate(self, magnitude):
        """
        negate negates the field value.  The existing field value is modified.
        The caller must provide the magnitude of the field value for a correct
        result.

        The field value is returned to support chaining, enabling syntax like:
            f.negate().addInt(1)
        so that:
            f = -f + 1

        Preconditions:
          - The max magnitude MUST be 63.
        Output Normalized: No
        Output Max Magnitude: Input magnitude + 1

        Args:
            magnitude (integer): the magnitude of the field value.

        Return:
            FieldVal: the object itself.
        """
        return self.negateVal(self, magnitude)

    def negateVal(self, val, magnitude):
        """
        negateVal negates the passed value and stores the result in f.  The
        caller must provide the magnitude of the passed value for a correct
        result.

        The field value is returned to support chaining, enabling syntax like:
            f.negateVal(f2).addInt(1)
        so that:
            f = -f2 + 1

        Preconditions:
          - The max magnitude MUST be 63.
        Output Normalized: No
        Output Max Magnitude: Input magnitude + 1

        Args:
            val (FieldVal): the field value to be negated.
            magnitude (integer): the magnitude of the field value.

        Return:
            FieldVal: the object itself.
        """
        # Negation in the field is just the prime minus the value.  However,
        # in order to allow negation against a field value without having to
        # normalize/reduce it first, multiply by the magnitude (that is how
        # "far" away it is from the normalized value) to adjust.  Also, since
        # negating a value pushes it one more order of magnitude away from the
        # normalized range, add 1 to compensate.

        # For some intuition here, imagine you're performing mod 12 arithmetic
        # (picture a clock) and you are negating the number 7.  So you start at
        # 12 (which is of course 0 under mod 12) and count backwards (left on
        # the clock) 7 times to arrive at 5.  Notice this is just 12-7 = 5.
        # Now, assume you're starting with 19, which is a number that is
        # already larger than the modulus and congruent to 7 (mod 12).  When a
        # value is already in the desired range, its magnitude is 1.  Since 19
        # is an additional "step", its magnitude (mod 12) is 2.  Since any
        # multiple of the modulus is conguent to zero (mod m), the answer can
        # be shortcut by simply multiplying the magnitude by the modulus and
        # subtracting.  Keeping with the example, this would be (2*12)-19 = 5.
        self.n[0] = (magnitude + 1) * fieldPrimeWordZero - val.n[0]
        self.n[1] = (magnitude + 1) * fieldPrimeWordOne - val.n[1]
        self.n[2] = (magnitude + 1) * fieldBaseMask - val.n[2]
        self.n[3] = (magnitude + 1) * fieldBaseMask - val.n[3]
        self.n[4] = (magnitude + 1) * fieldBaseMask - val.n[4]
        self.n[5] = (magnitude + 1) * fieldBaseMask - val.n[5]
        self.n[6] = (magnitude + 1) * fieldBaseMask - val.n[6]
        self.n[7] = (magnitude + 1) * fieldBaseMask - val.n[7]
        self.n[8] = (magnitude + 1) * fieldBaseMask - val.n[8]
        self.n[9] = (magnitude + 1) * fieldMSBMask - val.n[9]
        return self

    def add(self, val):
        """
        add adds the passed value to the existing field value and stores the
        result in f.

        The field value is returned to support chaining, enabling syntax like:
            f.add(f2).addInt(1)
        so that:
            f = f + f2 + 1

        Preconditions:
          - The sum of the magnitudes of the two field values MUST be a max of
            64.
        Output Normalized: No
        Output Max Magnitude: Sum of the magnitude of the two individual field
            values.

        Args:
            val (FieldVal): the field value to be added.

        Return:
            FieldVal: the object itself.
        """
        # Since the field representation intentionally provides overflow bits,
        # it's ok to use carryless addition as the carry bit is safely part of
        # each word and will be normalized out.  This could obviously be done
        # in a loop, but the unrolled version is faster.
        self.n[0] += val.n[0]
        self.n[1] += val.n[1]
        self.n[2] += val.n[2]
        self.n[3] += val.n[3]
        self.n[4] += val.n[4]
        self.n[5] += val.n[5]
        self.n[6] += val.n[6]
        self.n[7] += val.n[7]
        self.n[8] += val.n[8]
        self.n[9] += val.n[9]
        return self

    def square(self):
        """
        square squares the field value.  The existing field value is modified.
        Note that this function can overflow if multiplying any of the
        individual words exceeds a max uint32.  In practice, this means the
        magnitude of the field must be a max of 8 to prevent overflow.

        The field value is returned to support chaining, enabling syntax like:
            f.square().mul(f2)
        so that:
            f = f^2 * f2

        Preconditions:
          - The field value MUST have a max magnitude of 8.
        Output Normalized: No
        Output Max Magnitude: 1

        Return:
            FieldVal: the object itself.
        """
        return self.squareVal(self)

    def squareVal(self, val):
        """
        SquareVal squares the passed value and stores the result in f. Note
        that this function can overflow if multiplying any of the individual
        words exceeds a max uint32.  In practice, this means the magnitude of
        the field being squared must be a max of 8 to prevent overflow.

        The field value is returned to support chaining, enabling syntax like:
            f3.squareVal(f).mul(f)
        so that:
            f3 = f^2 * f2 = f^3

        Preconditions:
          - The field value MUST have a max magnitude of 8.
        Output Normalized: No
        Output Max Magnitude: 1

        Args:
            val (FieldVal): the field value to be squared.

        Return:
            FieldVal: the object itself.
        """
        # This could be done with a couple of for loops and an array to store
        # the intermediate terms, but this unrolled version is significantly
        # faster.

        # Terms for 2^(fieldBase*0).
        m = val.n[0] * val.n[0]
        t0 = m & fieldBaseMask

        # Terms for 2^(fieldBase*1).
        m = (m >> fieldBase) + 2 * val.n[0] * val.n[1]
        t1 = m & fieldBaseMask

        # Terms for 2^(fieldBase*2).
        m = (m >> fieldBase) + 2 * val.n[0] * val.n[2] + val.n[1] * val.n[1]
        t2 = m & fieldBaseMask

        # Terms for 2^(fieldBase*3).
        m = (m >> fieldBase) + 2 * val.n[0] * val.n[3] + 2 * val.n[1] * val.n[2]
        t3 = m & fieldBaseMask

        # Terms for 2^(fieldBase*4).
        m = (
            (m >> fieldBase)
            + 2 * val.n[0] * val.n[4]
            + 2 * val.n[1] * val.n[3]
            + val.n[2] * val.n[2]
        )
        t4 = m & fieldBaseMask

        # Terms for 2^(fieldBase*5).
        m = (
            (m >> fieldBase)
            + 2 * val.n[0] * val.n[5]
            + 2 * val.n[1] * val.n[4]
            + 2 * val.n[2] * val.n[3]
        )
        t5 = m & fieldBaseMask

        # Terms for 2^(fieldBase*6).
        m = (
            (m >> fieldBase)
            + 2 * val.n[0] * val.n[6]
            + 2 * val.n[1] * val.n[5]
            + 2 * val.n[2] * val.n[4]
            + val.n[3] * val.n[3]
        )
        t6 = m & fieldBaseMask

        # Terms for 2^(fieldBase*7).
        m = (
            (m >> fieldBase)
            + 2 * val.n[0] * val.n[7]
            + 2 * val.n[1] * val.n[6]
            + 2 * val.n[2] * val.n[5]
            + 2 * val.n[3] * val.n[4]
        )
        t7 = m & fieldBaseMask

        # Terms for 2^(fieldBase*8).
        m = (
            (m >> fieldBase)
            + 2 * val.n[0] * val.n[8]
            + 2 * val.n[1] * val.n[7]
            + 2 * val.n[2] * val.n[6]
            + 2 * val.n[3] * val.n[5]
            + val.n[4] * val.n[4]
        )
        t8 = m & fieldBaseMask

        # Terms for 2^(fieldBase*9).
        m = (
            (m >> fieldBase)
            + 2 * val.n[0] * val.n[9]
            + 2 * val.n[1] * val.n[8]
            + 2 * val.n[2] * val.n[7]
            + 2 * val.n[3] * val.n[6]
            + 2 * val.n[4] * val.n[5]
        )
        t9 = m & fieldBaseMask

        # Terms for 2^(fieldBase*10).
        m = (
            (m >> fieldBase)
            + 2 * val.n[1] * val.n[9]
            + 2 * val.n[2] * val.n[8]
            + 2 * val.n[3] * val.n[7]
            + 2 * val.n[4] * val.n[6]
            + val.n[5] * val.n[5]
        )
        t10 = m & fieldBaseMask

        # Terms for 2^(fieldBase*11).
        m = (
            (m >> fieldBase)
            + 2 * val.n[2] * val.n[9]
            + 2 * val.n[3] * val.n[8]
            + 2 * val.n[4] * val.n[7]
            + 2 * val.n[5] * val.n[6]
        )
        t11 = m & fieldBaseMask

        # Terms for 2^(fieldBase*12).
        m = (
            (m >> fieldBase)
            + 2 * val.n[3] * val.n[9]
            + 2 * val.n[4] * val.n[8]
            + 2 * val.n[5] * val.n[7]
            + val.n[6] * val.n[6]
        )
        t12 = m & fieldBaseMask

        # Terms for 2^(fieldBase*13).
        m = (
            (m >> fieldBase)
            + 2 * val.n[4] * val.n[9]
            + 2 * val.n[5] * val.n[8]
            + 2 * val.n[6] * val.n[7]
        )
        t13 = m & fieldBaseMask

        # Terms for 2^(fieldBase*14).
        m = (
            (m >> fieldBase)
            + 2 * val.n[5] * val.n[9]
            + 2 * val.n[6] * val.n[8]
            + val.n[7] * val.n[7]
        )
        t14 = m & fieldBaseMask

        # Terms for 2^(fieldBase*15).
        m = (m >> fieldBase) + 2 * val.n[6] * val.n[9] + 2 * val.n[7] * val.n[8]
        t15 = m & fieldBaseMask

        # Terms for 2^(fieldBase*16).
        m = (m >> fieldBase) + 2 * val.n[7] * val.n[9] + val.n[8] * val.n[8]
        t16 = m & fieldBaseMask

        # Terms for 2^(fieldBase*17).
        m = (m >> fieldBase) + 2 * val.n[8] * val.n[9]
        t17 = m & fieldBaseMask

        # Terms for 2^(fieldBase*18).
        m = (m >> fieldBase) + val.n[9] * val.n[9]
        t18 = m & fieldBaseMask

        # What's left is for 2^(fieldBase*19).
        t19 = m >> fieldBase

        # At this point, all of the terms are grouped into their respective
        # base.

        # Per [HAC] section 14.3.4: Reduction method of moduli of special form,
        # when the modulus is of the special form m = b^t - c, highly efficient
        # reduction can be achieved per the provided algorithm.

        # The secp256k1 prime is equivalent to 2^256 - 4294968273, so it fits
        # this criteria.

        # 4294968273 in field representation (base 2^26) is:
        # n[0] = 977
        # n[1] = 64
        # That is to say (2^26 * 64) + 977 = 4294968273

        # Since each word is in base 26, the upper terms (t10 and up) start
        # at 260 bits (versus the final desired range of 256 bits), so the
        # field representation of 'c' from above needs to be adjusted for the
        # extra 4 bits by multiplying it by 2^4 = 16.  4294968273 * 16 =
        # 68719492368.  Thus, the adjusted field representation of 'c' is:
        # n[0] = 977 * 16 = 15632
        # n[1] = 64 * 16 = 1024
        # That is to say (2^26 * 1024) + 15632 = 68719492368

        # To reduce the final term, t19, the entire 'c' value is needed instead
        # of only n[0] because there are no more terms left to handle n[1].
        # This means there might be some magnitude left in the upper bits that
        # is handled below.
        m = t0 + t10 * 15632
        t0 = m & fieldBaseMask
        m = (m >> fieldBase) + t1 + t10 * 1024 + t11 * 15632
        t1 = m & fieldBaseMask
        m = (m >> fieldBase) + t2 + t11 * 1024 + t12 * 15632
        t2 = m & fieldBaseMask
        m = (m >> fieldBase) + t3 + t12 * 1024 + t13 * 15632
        t3 = m & fieldBaseMask
        m = (m >> fieldBase) + t4 + t13 * 1024 + t14 * 15632
        t4 = m & fieldBaseMask
        m = (m >> fieldBase) + t5 + t14 * 1024 + t15 * 15632
        t5 = m & fieldBaseMask
        m = (m >> fieldBase) + t6 + t15 * 1024 + t16 * 15632
        t6 = m & fieldBaseMask
        m = (m >> fieldBase) + t7 + t16 * 1024 + t17 * 15632
        t7 = m & fieldBaseMask
        m = (m >> fieldBase) + t8 + t17 * 1024 + t18 * 15632
        t8 = m & fieldBaseMask
        m = (m >> fieldBase) + t9 + t18 * 1024 + t19 * primePartBy16
        t9 = m & fieldMSBMask
        m = m >> fieldMSBBits

        # At this point, if the magnitude is greater than 0, the overall value
        # is greater than the max possible 256-bit value.  In particular, it is
        # "how many times larger" than the max value it is.

        # The algorithm presented in [HAC] section 14.3.4 repeats until the
        # quotient is zero.  However, due to the above, we already know at
        # least how many times we would need to repeat as it's the value
        # currently in m.  Thus we can simply multiply the magnitude by the
        # field representation of the prime and do a single iteration.  Notice
        # that nothing will be changed when the magnitude is zero, so we could
        # skip this in that case, however always running regardless allows it
        # to run in constant time.  The final result will be in the range
        # 0 <= result <= prime + (2^64 - c), so it is guaranteed to have a
        # magnitude of 1, but it is denormalized.
        n = t0 + m * 977
        self.n[0] = n & fieldBaseMask
        n = (n >> fieldBase) + t1 + m * 64
        self.n[1] = n & fieldBaseMask
        self.n[2] = (n >> fieldBase) + t2
        self.n[3] = t3
        self.n[4] = t4
        self.n[5] = t5
        self.n[6] = t6
        self.n[7] = t7
        self.n[8] = t8
        self.n[9] = t9

        return self

    def mulInt(self, val):
        """
        mulInt multiplies the field value by the passed integer and stores the
        result in f.  Note that this function can overflow if multiplying the
        value by any of the individual words exceeds a max uint32.  Therefore
        it is important that the caller ensures no overflows will occur before
        using this function.

        The field value is returned to support chaining, enabling syntax like:
            f.mulInt(2).add(f2)
        so that:
            f = f * 2 + f2

        Preconditions:
          - The field value magnitude multiplied by given val MUST be a max of
            64.
        Output Normalized: No
        Output Max Magnitude: Existing field magnitude times the provided
            integer val.

        Args:
            val (int): the integer to be multiplied.

        Return:
            FieldVal: the object itself.
        """
        # Since each word of the field representation can hold up to
        # 32 - fieldBase extra bits which will be normalized out, it's safe
        # to multiply each word without using a larger type or carry
        # propagation so long as the values won't overflow a uint32.  This
        # could obviously be done in a loop, but the unrolled version is
        # faster.
        self.n[0] *= val
        self.n[1] *= val
        self.n[2] *= val
        self.n[3] *= val
        self.n[4] *= val
        self.n[5] *= val
        self.n[6] *= val
        self.n[7] *= val
        self.n[8] *= val
        self.n[9] *= val
        return self

    def mul(self, f):
        """
        mul multiplies the passed value to the existing field value and stores
        the result in f.  Note that this function can overflow if multiplying
        any of the individual words exceeds a max uint32.  In practice, this
        means the magnitude of either value involved in the multiplication must
        be a max of 8.

        The field value is returned to support chaining, enabling syntax like:
            f.mul(f2).addInt(1)
        so that:
            f = f * f2 + 1

        Preconditions:
          - Both field values MUST have a max magnitude of 8.
        Output Normalized: No
        Output Max Magnitude: 1

        Args:
            val (FieldVal): the field value to be multiplied.

        Return:
            FieldVal: the object itself.
        """
        return self.mul2(self, f)

    def mul2(self, val, val2):
        """
        mul multiplies the passed value to the existing field value and stores
        the result in f.  Note that this function can overflow if multiplying
        any of the individual words exceeds a max uint32.  In practice, this
        means the magnitude of either value involved in the multiplication must
        be a max of 8.

        The field value is returned to support chaining, enabling syntax like:
            f3.mul2(f, f2).addInt(1)
        so that:
            f3 = f * f2 + 1

        Preconditions:
          - Both input field values MUST have a max magnitude of 8.
        Output Normalized: No
        Output Max Magnitude: 1

        Args:
            val (FieldVal): the first field value to be multiplied.
            val2 (FieldVal): the second field value to be multiplied.

        Return:
            FieldVal: the object itself.
        """
        # This could be done with a couple of for loops and an array to store
        # the intermediate terms, but this unrolled version is significantly
        # faster.

        # Terms for 2^(fieldBase*0).
        m = val.n[0] * val2.n[0]
        t0 = m & fieldBaseMask

        # Terms for 2^(fieldBase*1).
        m = (m >> fieldBase) + val.n[0] * val2.n[1] + val.n[1] * val2.n[0]
        t1 = m & fieldBaseMask

        # Terms for 2^(fieldBase*2).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[2]
            + val.n[1] * val2.n[1]
            + val.n[2] * val2.n[0]
        )
        t2 = m & fieldBaseMask

        # Terms for 2^(fieldBase*3).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[3]
            + val.n[1] * val2.n[2]
            + val.n[2] * val2.n[1]
            + val.n[3] * val2.n[0]
        )
        t3 = m & fieldBaseMask

        # Terms for 2^(fieldBase*4).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[4]
            + val.n[1] * val2.n[3]
            + val.n[2] * val2.n[2]
            + val.n[3] * val2.n[1]
            + val.n[4] * val2.n[0]
        )
        t4 = m & fieldBaseMask

        # Terms for 2^(fieldBase*5).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[5]
            + val.n[1] * val2.n[4]
            + val.n[2] * val2.n[3]
            + val.n[3] * val2.n[2]
            + val.n[4] * val2.n[1]
            + val.n[5] * val2.n[0]
        )
        t5 = m & fieldBaseMask

        # Terms for 2^(fieldBase*6).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[6]
            + val.n[1] * val2.n[5]
            + val.n[2] * val2.n[4]
            + val.n[3] * val2.n[3]
            + val.n[4] * val2.n[2]
            + val.n[5] * val2.n[1]
            + val.n[6] * val2.n[0]
        )
        t6 = m & fieldBaseMask

        # Terms for 2^(fieldBase*7).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[7]
            + val.n[1] * val2.n[6]
            + val.n[2] * val2.n[5]
            + val.n[3] * val2.n[4]
            + val.n[4] * val2.n[3]
            + val.n[5] * val2.n[2]
            + val.n[6] * val2.n[1]
            + val.n[7] * val2.n[0]
        )
        t7 = m & fieldBaseMask

        # Terms for 2^(fieldBase*8).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[8]
            + val.n[1] * val2.n[7]
            + val.n[2] * val2.n[6]
            + val.n[3] * val2.n[5]
            + val.n[4] * val2.n[4]
            + val.n[5] * val2.n[3]
            + val.n[6] * val2.n[2]
            + val.n[7] * val2.n[1]
            + val.n[8] * val2.n[0]
        )
        t8 = m & fieldBaseMask

        # Terms for 2^(fieldBase*9).
        m = (
            (m >> fieldBase)
            + val.n[0] * val2.n[9]
            + val.n[1] * val2.n[8]
            + val.n[2] * val2.n[7]
            + val.n[3] * val2.n[6]
            + val.n[4] * val2.n[5]
            + val.n[5] * val2.n[4]
            + val.n[6] * val2.n[3]
            + val.n[7] * val2.n[2]
            + val.n[8] * val2.n[1]
            + val.n[9] * val2.n[0]
        )
        t9 = m & fieldBaseMask

        # Terms for 2^(fieldBase*10).
        m = (
            (m >> fieldBase)
            + val.n[1] * val2.n[9]
            + val.n[2] * val2.n[8]
            + val.n[3] * val2.n[7]
            + val.n[4] * val2.n[6]
            + val.n[5] * val2.n[5]
            + val.n[6] * val2.n[4]
            + val.n[7] * val2.n[3]
            + val.n[8] * val2.n[2]
            + val.n[9] * val2.n[1]
        )
        t10 = m & fieldBaseMask

        # Terms for 2^(fieldBase*11).
        m = (
            (m >> fieldBase)
            + val.n[2] * val2.n[9]
            + val.n[3] * val2.n[8]
            + val.n[4] * val2.n[7]
            + val.n[5] * val2.n[6]
            + val.n[6] * val2.n[5]
            + val.n[7] * val2.n[4]
            + val.n[8] * val2.n[3]
            + val.n[9] * val2.n[2]
        )
        t11 = m & fieldBaseMask

        # Terms for 2^(fieldBase*12).
        m = (
            (m >> fieldBase)
            + val.n[3] * val2.n[9]
            + val.n[4] * val2.n[8]
            + val.n[5] * val2.n[7]
            + val.n[6] * val2.n[6]
            + val.n[7] * val2.n[5]
            + val.n[8] * val2.n[4]
            + val.n[9] * val2.n[3]
        )
        t12 = m & fieldBaseMask

        # Terms for 2^(fieldBase*13).
        m = (
            (m >> fieldBase)
            + val.n[4] * val2.n[9]
            + val.n[5] * val2.n[8]
            + val.n[6] * val2.n[7]
            + val.n[7] * val2.n[6]
            + val.n[8] * val2.n[5]
            + val.n[9] * val2.n[4]
        )
        t13 = m & fieldBaseMask

        # Terms for 2^(fieldBase*14).
        m = (
            (m >> fieldBase)
            + val.n[5] * val2.n[9]
            + val.n[6] * val2.n[8]
            + val.n[7] * val2.n[7]
            + val.n[8] * val2.n[6]
            + val.n[9] * val2.n[5]
        )
        t14 = m & fieldBaseMask

        # Terms for 2^(fieldBase*15).
        m = (
            (m >> fieldBase)
            + val.n[6] * val2.n[9]
            + val.n[7] * val2.n[8]
            + val.n[8] * val2.n[7]
            + val.n[9] * val2.n[6]
        )
        t15 = m & fieldBaseMask

        # Terms for 2^(fieldBase*16).
        m = (
            (m >> fieldBase)
            + val.n[7] * val2.n[9]
            + val.n[8] * val2.n[8]
            + val.n[9] * val2.n[7]
        )
        t16 = m & fieldBaseMask

        # Terms for 2^(fieldBase*17).
        m = (m >> fieldBase) + val.n[8] * val2.n[9] + val.n[9] * val2.n[8]
        t17 = m & fieldBaseMask

        # Terms for 2^(fieldBase*18).
        m = (m >> fieldBase) + val.n[9] * val2.n[9]
        t18 = m & fieldBaseMask

        # What's left is for 2^(fieldBase*19).
        t19 = m >> fieldBase

        # At this point, all of the terms are grouped into their respective
        # base.
        #
        # Per [HAC] section 14.3.4: Reduction method of moduli of special form,
        # when the modulus is of the special form m = b^t - c, highly efficient
        # reduction can be achieved per the provided algorithm.

        # The secp256k1 prime is equivalent to 2^256 - 4294968273, so it fits
        # this criteria.

        # 4294968273 in field representation (base 2^26) is:
        # n[0] = 977
        # n[1] = 64
        # That is to say (2^26 * 64) + 977 = 4294968273

        # Since each word is in base 26, the upper terms (t10 and up) start
        # at 260 bits (versus the final desired range of 256 bits), so the
        # field representation of 'c' from above needs to be adjusted for the
        # extra 4 bits by multiplying it by 2^4 = 16.  4294968273 * 16 =
        # 68719492368.  Thus, the adjusted field representation of 'c' is:
        # n[0] = 977 * 16 = 15632
        # n[1] = 64 * 16 = 1024
        # That is to say (2^26 * 1024) + 15632 = 68719492368

        # To reduce the final term, t19, the entire 'c' value is needed instead
        # of only n[0] because there are no more terms left to handle n[1].
        # This means there might be some magnitude left in the upper bits that
        # is handled below.
        m = t0 + t10 * 15632
        t0 = m & fieldBaseMask
        m = (m >> fieldBase) + t1 + t10 * 1024 + t11 * 15632
        t1 = m & fieldBaseMask
        m = (m >> fieldBase) + t2 + t11 * 1024 + t12 * 15632
        t2 = m & fieldBaseMask
        m = (m >> fieldBase) + t3 + t12 * 1024 + t13 * 15632
        t3 = m & fieldBaseMask
        m = (m >> fieldBase) + t4 + t13 * 1024 + t14 * 15632
        t4 = m & fieldBaseMask
        m = (m >> fieldBase) + t5 + t14 * 1024 + t15 * 15632
        t5 = m & fieldBaseMask
        m = (m >> fieldBase) + t6 + t15 * 1024 + t16 * 15632
        t6 = m & fieldBaseMask
        m = (m >> fieldBase) + t7 + t16 * 1024 + t17 * 15632
        t7 = m & fieldBaseMask
        m = (m >> fieldBase) + t8 + t17 * 1024 + t18 * 15632
        t8 = m & fieldBaseMask
        m = (m >> fieldBase) + t9 + t18 * 1024 + t19 * primePartBy16
        t9 = m & fieldMSBMask
        m = m >> fieldMSBBits

        # At this point, if the magnitude is greater than 0, the overall value
        # is greater than the max possible 256-bit value.  In particular, it is
        # "how many times larger" than the max value it is.

        # The algorithm presented in [HAC] section 14.3.4 repeats until the
        # quotient is zero.  However, due to the above, we already know at
        # least how many times we would need to repeat as it's the value
        # currently in m.  Thus we can simply multiply the magnitude by the
        # field representation of the prime and do a single iteration.  Notice
        # that nothing will be changed when the magnitude is zero, so we could
        # skip this in that case, however always running regardless allows it
        # to run in constant time.  The final result will be in the range
        # 0 <= result <= prime + (2^64 - c), so it is guaranteed to have a
        # magnitude of 1, but it is denormalized.
        d = t0 + m * 977
        self.n[0] = d & fieldBaseMask
        d = (d >> fieldBase) + t1 + m * 64
        self.n[1] = d & fieldBaseMask
        self.n[2] = (d >> fieldBase) + t2
        self.n[3] = t3
        self.n[4] = t4
        self.n[5] = t5
        self.n[6] = t6
        self.n[7] = t7
        self.n[8] = t8
        self.n[9] = t9
        return self

    def add2(self, val, val2):
        """
        add2 adds the passed two field values together and stores the result in
        f.

        The field value is returned to support chaining, enabling syntax like:
            f3.add2(f, f2).addInt(1)
        so that:
            f3 = f + f2 + 1

        Preconditions:
          - The sum of the magnitudes of the two field values MUST be a max of
            64.
        Output Normalized: No
        Output Max Magnitude: Sum of the magnitude of the two field values.

        Args:
            val (FieldVal): the first field value to be added.
            val2 (FieldVal): the second field value to be added.

        Return:
            FieldVal: the object itself.
        """
        # Since the field representation intentionally provides overflow bits,
        # it's ok to use carryless addition as the carry bit is safely part of
        # each word and will be normalized out.  This could obviously be done
        # in a loop, but the unrolled version is faster.
        self.n[0] = val.n[0] + val2.n[0]
        self.n[1] = val.n[1] + val2.n[1]
        self.n[2] = val.n[2] + val2.n[2]
        self.n[3] = val.n[3] + val2.n[3]
        self.n[4] = val.n[4] + val2.n[4]
        self.n[5] = val.n[5] + val2.n[5]
        self.n[6] = val.n[6] + val2.n[6]
        self.n[7] = val.n[7] + val2.n[7]
        self.n[8] = val.n[8] + val2.n[8]
        self.n[9] = val.n[9] + val2.n[9]
        return self

    def putBytes(self, b):
        """
        putBytes unpacks the field value to a 32-byte big-endian value using the
        passed bytearray.  There is a similar function, bytes, which unpacks the
        field value into a new array and returns that.  This version is provided
        since it can be useful to cut down on the number of allocations by
        allowing the caller to reuse a bytearray.

        Preconditions:
          - The field value MUST be normalized.

        Args:
            b (bytes-like): the bytearray value to be set as the field value.
        """
        # Unpack the 256 total bits from the 10 uint32 words with a max of
        # 26-bits per word.  This could be done with a couple of for loops,
        # but this unrolled version is faster.
        f = self
        b[31] = f.n[0] & eightBitsMask
        b[30] = (f.n[0] >> 8) & eightBitsMask
        b[29] = (f.n[0] >> 16) & eightBitsMask
        b[28] = (f.n[0] >> 24) & twoBitsMask | (f.n[1] & sixBitsMask) << 2
        b[27] = (f.n[1] >> 6) & eightBitsMask
        b[26] = (f.n[1] >> 14) & eightBitsMask
        b[25] = (f.n[1] >> 22) & fourBitsMask | (f.n[2] & fourBitsMask) << 4
        b[24] = (f.n[2] >> 4) & eightBitsMask
        b[23] = (f.n[2] >> 12) & eightBitsMask
        b[22] = (f.n[2] >> 20) & sixBitsMask | (f.n[3] & twoBitsMask) << 6
        b[21] = (f.n[3] >> 2) & eightBitsMask
        b[20] = (f.n[3] >> 10) & eightBitsMask
        b[19] = (f.n[3] >> 18) & eightBitsMask
        b[18] = f.n[4] & eightBitsMask
        b[17] = (f.n[4] >> 8) & eightBitsMask
        b[16] = (f.n[4] >> 16) & eightBitsMask
        b[15] = (f.n[4] >> 24) & twoBitsMask | (f.n[5] & sixBitsMask) << 2
        b[14] = (f.n[5] >> 6) & eightBitsMask
        b[13] = (f.n[5] >> 14) & eightBitsMask
        b[12] = (f.n[5] >> 22) & fourBitsMask | (f.n[6] & fourBitsMask) << 4
        b[11] = (f.n[6] >> 4) & eightBitsMask
        b[10] = (f.n[6] >> 12) & eightBitsMask
        b[9] = (f.n[6] >> 20) & sixBitsMask | (f.n[7] & twoBitsMask) << 6
        b[8] = (f.n[7] >> 2) & eightBitsMask
        b[7] = (f.n[7] >> 10) & eightBitsMask
        b[6] = (f.n[7] >> 18) & eightBitsMask
        b[5] = f.n[8] & eightBitsMask
        b[4] = (f.n[8] >> 8) & eightBitsMask
        b[3] = (f.n[8] >> 16) & eightBitsMask
        b[2] = (f.n[8] >> 24) & twoBitsMask | (f.n[9] & sixBitsMask) << 2
        b[1] = (f.n[9] >> 6) & eightBitsMask
        b[0] = (f.n[9] >> 14) & eightBitsMask

    def bytes(self):
        """
        bytes unpacks the field value to a 32-byte big-endian bytearray.  See
        putBytes for a variant that allows a bytearray to be passed, which can
        be useful to cut down on the number of allocations by allowing the
        caller to reuse a bytearray.

        Preconditions:
          - The field value MUST be normalized.

        Return:
            bytearray: the field value converted to a 32-byte bytearray.
        """
        b = bytearray(32)
        self.putBytes(b)
        return b

    def string(self):
        """
        string returns the field value as a human-readable hex string.

        Preconditions: None
        Output Normalized: Same as input value.
        Output Max Magnitude: Same as input value.
        """
        # Make a copy of the field value, so that we can normalize the copy
        # without changing the original value.
        f = FieldVal().set(self).normalize()
        return f.bytes().hex()

    def inverse(self):
        """
        inverse finds the modular multiplicative inverse of the field value.
        The existing field value is modified.

        The field value is returned to support chaining, enabling syntax like:
            f.inverse().mul(f2)
        so that:
            f = f^-1 * f2

        Preconditions:
          - The field value MUST have a max magnitude of 8.
        Output Normalized: No
        Output Max Magnitude: 1

        Return:
            FieldVal: the object itself.
        """
        # Fermat's little theorem states that for a nonzero number a and prime
        # prime p, a^(p-1) = 1 (mod p).  Since the multiplicative inverse is
        # a*b = 1 (mod p), it follows that b = a*a^(p-2) = a^(p-1) = 1 (mod p).
        # Thus, a^(p-2) is the multiplicative inverse.

        # In order to efficiently compute a^(p-2), p-2 needs to be split into
        # a sequence of squares and multiplications that minimizes the number
        # of multiplications needed (since they are more costly than
        # squarings). Intermediate results are saved and reused as well.

        # The secp256k1 prime - 2 is 2^256 - 4294968275.

        # This has a cost of 258 field squarings and 33 field multiplications.

        # fmt: off
        f = self
        fv = FieldVal
        a2, a3, a4, a10, a11, a21, a42, a45, a63, a1019, a1023 = (
            fv(), fv(), fv(), fv(), fv(), fv(), fv(), fv(), fv(), fv(), fv(),
        )
        a2.squareVal(f)
        a3.mul2(a2, f)
        a4.squareVal(a2)
        a10.squareVal(a4).mul(a2)
        a11.mul2(a10, f)
        a21.mul2(a10, a11)
        a42.squareVal(a21)
        a45.mul2(a42, a3)
        a63.mul2(a42, a21)
        a1019.squareVal(a63).square().square().square().mul(a11)
        a1023.mul2(a1019, a4)
        f.set(a63)                                      # f = a^(2^6 - 1)
        f.square().square().square().square().square()  # f = a^(2^11 - 32)
        f.square().square().square().square().square()  # f = a^(2^16 - 1024)
        f.mul(a1023)                                    # f = a^(2^16 - 1)
        f.square().square().square().square().square()  # f = a^(2^21 - 32)
        f.square().square().square().square().square()  # f = a^(2^26 - 1024)
        f.mul(a1023)                                    # f = a^(2^26 - 1)
        f.square().square().square().square().square()  # f = a^(2^31 - 32)
        f.square().square().square().square().square()  # f = a^(2^36 - 1024)
        f.mul(a1023)                                    # f = a^(2^36 - 1)
        f.square().square().square().square().square()  # f = a^(2^41 - 32)
        f.square().square().square().square().square()  # f = a^(2^46 - 1024)
        f.mul(a1023)                                    # f = a^(2^46 - 1)
        f.square().square().square().square().square()  # f = a^(2^51 - 32)
        f.square().square().square().square().square()  # f = a^(2^56 - 1024)
        f.mul(a1023)                                    # f = a^(2^56 - 1)
        f.square().square().square().square().square()  # f = a^(2^61 - 32)
        f.square().square().square().square().square()  # f = a^(2^66 - 1024)
        f.mul(a1023)                                    # f = a^(2^66 - 1)
        f.square().square().square().square().square()  # f = a^(2^71 - 32)
        f.square().square().square().square().square()  # f = a^(2^76 - 1024)
        f.mul(a1023)                                    # f = a^(2^76 - 1)
        f.square().square().square().square().square()  # f = a^(2^81 - 32)
        f.square().square().square().square().square()  # f = a^(2^86 - 1024)
        f.mul(a1023)                                    # f = a^(2^86 - 1)
        f.square().square().square().square().square()  # f = a^(2^91 - 32)
        f.square().square().square().square().square()  # f = a^(2^96 - 1024)
        f.mul(a1023)                                    # f = a^(2^96 - 1)
        f.square().square().square().square().square()  # f = a^(2^101 - 32)
        f.square().square().square().square().square()  # f = a^(2^106 - 1024)
        f.mul(a1023)                                    # f = a^(2^106 - 1)
        f.square().square().square().square().square()  # f = a^(2^111 - 32)
        f.square().square().square().square().square()  # f = a^(2^116 - 1024)
        f.mul(a1023)                                    # f = a^(2^116 - 1)
        f.square().square().square().square().square()  # f = a^(2^121 - 32)
        f.square().square().square().square().square()  # f = a^(2^126 - 1024)
        f.mul(a1023)                                    # f = a^(2^126 - 1)
        f.square().square().square().square().square()  # f = a^(2^131 - 32)
        f.square().square().square().square().square()  # f = a^(2^136 - 1024)
        f.mul(a1023)                                    # f = a^(2^136 - 1)
        f.square().square().square().square().square()  # f = a^(2^141 - 32)
        f.square().square().square().square().square()  # f = a^(2^146 - 1024)
        f.mul(a1023)                                    # f = a^(2^146 - 1)
        f.square().square().square().square().square()  # f = a^(2^151 - 32)
        f.square().square().square().square().square()  # f = a^(2^156 - 1024)
        f.mul(a1023)                                    # f = a^(2^156 - 1)
        f.square().square().square().square().square()  # f = a^(2^161 - 32)
        f.square().square().square().square().square()  # f = a^(2^166 - 1024)
        f.mul(a1023)                                    # f = a^(2^166 - 1)
        f.square().square().square().square().square()  # f = a^(2^171 - 32)
        f.square().square().square().square().square()  # f = a^(2^176 - 1024)
        f.mul(a1023)                                    # f = a^(2^176 - 1)
        f.square().square().square().square().square()  # f = a^(2^181 - 32)
        f.square().square().square().square().square()  # f = a^(2^186 - 1024)
        f.mul(a1023)                                    # f = a^(2^186 - 1)
        f.square().square().square().square().square()  # f = a^(2^191 - 32)
        f.square().square().square().square().square()  # f = a^(2^196 - 1024)
        f.mul(a1023)                                    # f = a^(2^196 - 1)
        f.square().square().square().square().square()  # f = a^(2^201 - 32)
        f.square().square().square().square().square()  # f = a^(2^206 - 1024)
        f.mul(a1023)                                    # f = a^(2^206 - 1)
        f.square().square().square().square().square()  # f = a^(2^211 - 32)
        f.square().square().square().square().square()  # f = a^(2^216 - 1024)
        f.mul(a1023)                                    # f = a^(2^216 - 1)
        f.square().square().square().square().square()  # f = a^(2^221 - 32)
        f.square().square().square().square().square()  # f = a^(2^226 - 1024)
        f.mul(a1019)                                    # f = a^(2^226 - 5)
        f.square().square().square().square().square()  # f = a^(2^231 - 160)
        f.square().square().square().square().square()  # f = a^(2^236 - 5120)
        f.mul(a1023)                                    # f = a^(2^236 - 4097)
        f.square().square().square().square().square()  # f = a^(2^241 - 131104)
        f.square().square().square().square().square()  # f = a^(2^246 - 4195328)
        f.mul(a1023)                                    # f = a^(2^246 - 4194305)
        f.square().square().square().square().square()  # f = a^(2^251 - 134217760)
        f.square().square().square().square().square()  # f = a^(2^256 - 4294968320)
        return f.mul(a45)      # f = a^(2^256 - 4294968275) = a^(p-2)
        # fmt: on


BytePoints = []


def loadS256BytePoints():
    assert len(secp256k1BytePoints), "basepoint string empty"

    # Decompress the pre-computed table used to accelerate scalar base
    # multiplication.
    compressed = b64decode(secp256k1BytePoints)
    serialized = zdecompress(compressed)

    # Deserialize the precomputed byte points and set the curve to them.
    offset = 0
    # var bytePoints [32][256][3]fieldVal
    ifunc = lambda b: int.from_bytes(b, byteorder="big")
    global BytePoints
    BytePoints = []
    for byteNum in range(32):
        row = []
        BytePoints.append(row)
        for i in range(256):
            col = []
            row.append(col)
            px = FieldVal()
            py = FieldVal()
            pz = FieldVal()
            col.append(px)
            col.append(py)
            col.append(pz)
            for j in range(10):
                px.n[j] = ifunc(serialized[offset + 3 : offset - 1 : -1])
                offset += 4
            for j in range(10):
                py.n[j] = ifunc(serialized[offset + 3 : offset - 1 : -1])
                offset += 4
            for j in range(10):
                pz.n[j] = ifunc(serialized[offset + 3 : offset - 1 : -1])
                offset += 4


loadS256BytePoints()
