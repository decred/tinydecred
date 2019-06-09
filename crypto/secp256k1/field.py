from tinydecred.crypto.bytearray import ByteArray
from base64 import b64decode
from bytepoints import secp256k1BytePoints
from zlib import decompress as zdecompress
import unittest

# Constants used to make the code more readable.
twoBitsMask   = 0x03
fourBitsMask  = 0x0f
sixBitsMask   = 0x3f
eightBitsMask = 0xff

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
fieldPrimeWordZero = 0x3fffc2f

# fieldPrimeWordOne is word one of the secp256k1 prime in the
# internal field representation.  It is used during negation.
fieldPrimeWordOne = 0x3ffffbf

"""
fieldVal implements optimized fixed-precision arithmetic over the
secp256k1 finite field.  This means all arithmetic is performed modulo
0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f.  It
represents each 256-bit value as 10 32-bit integers in base 2^26.  This
provides 6 bits of overflow in each word (10 bits in the most significant
word) for a total of 64 bits of overflow (9*6 + 10 = 64).  It only implements
the arithmetic needed for elliptic curve operations.

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

class FieldVal:
	def __init__(self):
		self.zero()
	def zero(self):
		self.n = [0]*10
	@staticmethod
	def fromHex(hexString): # string) *fieldVal {
		"""
		 SetHex decodes the passed big-endian hex string into the internal field value
		 representation.  Only the first 32-bytes are used.

		 The field value is returned to support chaining.  This enables syntax like:
		 #= new(fieldVal).SetHex("0abc").Add(1) so that f = 0x0abc + 1
		"""
		if len(hexString) % 2 != 0:
			hexString = "0" + hexString
		b = ByteArray(hexString)
		f = FieldVal()
		f.setBytes(b)
		return f
	@staticmethod
	def fromInt(i):
		f = FieldVal()
		return f.setInt(i)
	def setInt(self, i):
		self.zero()
		self.n[0] = i
		return self
	def equals(self, f):
		return all((x == y for x, y in zip(f.n, self.n)))
	def setBytes(self, b):
		b = ByteArray(b, length=32, copy=False)
		self.n[0] = b[31] | b[30]<<8 | b[29]<<16 |	(b[28]&twoBitsMask)<<24
		self.n[1] = b[28]>>2 | b[27]<<6 | b[26]<<14 | (b[25]&fourBitsMask)<<22
		self.n[2] = b[25]>>4 | b[24]<<4 | b[23]<<12 | (b[22]&sixBitsMask)<<20
		self.n[3] = b[22]>>6 | b[21]<<2 | b[20]<<10 | b[19]<<18
		self.n[4] = b[18] | b[17]<<8 | b[16]<<16 |	(b[15]&twoBitsMask)<<24
		self.n[5] = b[15]>>2 | b[14]<<6 | b[13]<<14 | (b[12]&fourBitsMask)<<22
		self.n[6] = b[12]>>4 | b[11]<<4 | b[10]<<12 | (b[9]&sixBitsMask)<<20
		self.n[7] = b[9]>>6 | b[8]<<2 | b[7]<<10 |	b[6]<<18
		self.n[8] = b[5] | b[4]<<8 | b[3]<<16 | (b[2]&twoBitsMask)<<24
		self.n[9] = b[2]>>2 | b[1]<<6 | b[0]<<14
	def isZero(self):
		return all((x == 0 for x in self.n))
	def set(self, f):
		self.n = [x for x in f.n]
		return self
	def normalize(self): # *fieldVal {
		"""
		Normalize normalizes the internal field words into the desired range and
		performs fast modular reduction over the secp256k1 prime by making use of the
		special form of the prime.
		"""
		# The field representation leaves 6 bits of overflow in each word so
		# intermediate calculations can be performed without needing to
		# propagate the carry to each higher word during the calculations.  In
		# order to normalize, we need to "compact" the full 256-bit value to
		# the right while propagating any carries through to the high order
		# word.
		# 		Since this field is doing arithmetic modulo the secp256k1 prime, we
		# also need to perform modular reduction over the prime.
		# 		Per [HAC] section 14.3.4: Reduction method of moduli of special form,
		# when the modulus is of the special form m = b^t - c, highly efficient
		# reduction can be achieved.
		# 		The secp256k1 prime is equivalent to 2^256 - 4294968273, so it fits
		# this criteria.
		# 		4294968273 in field representation (base 2^26) is:
		# n[0] = 977
		# n[1] = 64
		# That is to say (2^26 * 64) + 977 = 4294968273
		# 		The algorithm presented in the referenced section typically repeats
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
		t0 = f.n[0] + m*977
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

		# At this point, the magnitude is guaranteed to be one, however, the
		# value could still be greater than the prime if there was either a
		# carry through to bit 256 (bit 22 of the higher order word) or the
		# value is greater than or equal to the field characteristic.  The
		# following determines if either or these conditions are true and does
		# the final reduction in constant time.
		#
		# Note that the if/else statements here intentionally do the bitwise
		# operators even when it won't change the value to ensure constant time
		# between the branches.  Also note that 'm' will be zero when neither
		# of the aforementioned conditions are true and the value will not be
		# changed when 'm' is zero.
		m = 1
		if t9 == fieldMSBMask:
			m &= 1
		else:
			m &= 0
		if t2&t3&t4&t5&t6&t7&t8 == fieldBaseMask:
			m &= 1
		else:
			m &= 0
		if (((t0+977)>>fieldBase) + t1 + 64) > fieldBaseMask:
			m &= 1
		else:
			m &= 0
		if t9>>fieldMSBBits != 0:
			m |= 1
		else:
			m |= 0
		t0 = t0 + m*977
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
		t9 = t9 & fieldMSBMask # Remove potential multiple of 2^256.

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
	def negate(self, magnitude):  # uint32) *fieldVal {
		"""
		# Negate negates the field value.  The existing field value is modified.  The
		# caller must provide the magnitude of the field value for a correct result.
		#
		# The field value is returned to support chaining.  This enables syntax like:
		# f.Negate().AddInt(1) so that f = -f + 1.
		"""
		return self.negateVal(self, magnitude)
	def negateVal(self, val, magnitude): # val *fieldVal, magnitude uint32) *fieldVal {
		"""
		NegateVal negates the passed value and stores the result in f.  The caller
		must provide the magnitude of the passed value for a correct result.
				
		The field value is returned to support chaining.  This enables syntax like:
		f.NegateVal(f2).AddInt(1) so that f = -f2 + 1.
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
		# be shortcut by simply mulplying the magnitude by the modulus and
		# subtracting.  Keeping with the example, this would be (2*12)-19 = 5.
		self.n[0] = (magnitude+1)*fieldPrimeWordZero - val.n[0]
		self.n[1] = (magnitude+1)*fieldPrimeWordOne - val.n[1]
		self.n[2] = (magnitude+1)*fieldBaseMask - val.n[2]
		self.n[3] = (magnitude+1)*fieldBaseMask - val.n[3]
		self.n[4] = (magnitude+1)*fieldBaseMask - val.n[4]
		self.n[5] = (magnitude+1)*fieldBaseMask - val.n[5]
		self.n[6] = (magnitude+1)*fieldBaseMask - val.n[6]
		self.n[7] = (magnitude+1)*fieldBaseMask - val.n[7]
		self.n[8] = (magnitude+1)*fieldBaseMask - val.n[8]
		self.n[9] = (magnitude+1)*fieldMSBMask - val.n[9]
		return self
	
	def add(self, val): # *fieldVal) *fieldVal {
		"""
		Add adds the passed value to the existing field value and stores the result
		in f.

		The field value is returned to support chaining.  This enables syntax like:
		f.Add(f2).AddInt(1) so that f = f + f2 + 1.
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
		return self.squareVal(self)
	def squareVal(self, val): # *fieldVal) *fieldVal {
		"""
		SquareVal squares the passed value and stores the result in f.  Note that
		this function can overflow if multiplying any of the individual words
		exceeds a max uint32.  In practice, this means the magnitude of the field
		being squred must be a max of 8 to prevent overflow.
	
		The field value is returned to support chaining.  This enables syntax like:
		f3.SquareVal(f).Mul(f) so that f3 = f^2 * f = f^3.
		"""
		# This could be done with a couple of for loops and an array to store
		# the intermediate terms, but this unrolled version is significantly
		# faster.

		# Terms for 2^(fieldBase*0).
		m = val.n[0] * val.n[0]
		t0 = m & fieldBaseMask

		# Terms for 2^(fieldBase*1).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[1]
		t1 = m & fieldBaseMask

		# Terms for 2^(fieldBase*2).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[2] + val.n[1]*val.n[1]
		t2 = m & fieldBaseMask

		# Terms for 2^(fieldBase*3).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[3] + 2*val.n[1]*val.n[2]
		t3 = m & fieldBaseMask

		# Terms for 2^(fieldBase*4).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[4] + 2*val.n[1]*val.n[3] + val.n[2]*val.n[2]
		t4 = m & fieldBaseMask

		# Terms for 2^(fieldBase*5).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[5] + 2*val.n[1]*val.n[4] + 2*val.n[2]*val.n[3]
		t5 = m & fieldBaseMask

		# Terms for 2^(fieldBase*6).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[6] + 2*val.n[1]*val.n[5] + 2*val.n[2]*val.n[4] + val.n[3]*val.n[3]
		t6 = m & fieldBaseMask

		# Terms for 2^(fieldBase*7).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[7] + 2*val.n[1]*val.n[6] + 2*val.n[2]*val.n[5] + 2*val.n[3]*val.n[4]
		t7 = m & fieldBaseMask

		# Terms for 2^(fieldBase*8).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[8] + 2*val.n[1]*val.n[7] + 2*val.n[2]*val.n[6] + 2*val.n[3]*val.n[5] + val.n[4]*val.n[4]
		t8 = m & fieldBaseMask

		# Terms for 2^(fieldBase*9).
		m = (m >> fieldBase) + 2*val.n[0]*val.n[9] + 2*val.n[1]*val.n[8] + 2*val.n[2]*val.n[7] + 2*val.n[3]*val.n[6] + 2*val.n[4]*val.n[5]
		t9 = m & fieldBaseMask

		# Terms for 2^(fieldBase*10).
		m = (m >> fieldBase) + 2*val.n[1]*val.n[9] + 2*val.n[2]*val.n[8] + 2*val.n[3]*val.n[7] + 2*val.n[4]*val.n[6] + val.n[5]*val.n[5]
		t10 = m & fieldBaseMask

		# Terms for 2^(fieldBase*11).
		m = (m >> fieldBase) + 2*val.n[2]*val.n[9] + 2*val.n[3]*val.n[8] + 2*val.n[4]*val.n[7] + 2*val.n[5]*val.n[6]
		t11 = m & fieldBaseMask

		# Terms for 2^(fieldBase*12).
		m = (m >> fieldBase) + 2*val.n[3]*val.n[9] + 2*val.n[4]*val.n[8] + 2*val.n[5]*val.n[7] + val.n[6]*val.n[6]
		t12 = m & fieldBaseMask

		# Terms for 2^(fieldBase*13).
		m = (m >> fieldBase) + 2*val.n[4]*val.n[9] + 2*val.n[5]*val.n[8] + 2*val.n[6]*val.n[7]
		t13 = m & fieldBaseMask

		# Terms for 2^(fieldBase*14).
		m = (m >> fieldBase) + 2*val.n[5]*val.n[9] + 2*val.n[6]*val.n[8] + val.n[7]*val.n[7]
		t14 = m & fieldBaseMask

		# Terms for 2^(fieldBase*15).
		m = (m >> fieldBase) + 2*val.n[6]*val.n[9] + 2*val.n[7]*val.n[8]
		t15 = m & fieldBaseMask

		# Terms for 2^(fieldBase*16).
		m = (m >> fieldBase) + 2*val.n[7]*val.n[9] + val.n[8]*val.n[8]
		t16 = m & fieldBaseMask

		# Terms for 2^(fieldBase*17).
		m = (m >> fieldBase) + 2*val.n[8]*val.n[9]
		t17 = m & fieldBaseMask

		# Terms for 2^(fieldBase*18).
		m = (m >> fieldBase) + val.n[9]*val.n[9]
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
		m = t0 + t10*15632
		t0 = m & fieldBaseMask
		m = (m >> fieldBase) + t1 + t10*1024 + t11*15632
		t1 = m & fieldBaseMask
		m = (m >> fieldBase) + t2 + t11*1024 + t12*15632
		t2 = m & fieldBaseMask
		m = (m >> fieldBase) + t3 + t12*1024 + t13*15632
		t3 = m & fieldBaseMask
		m = (m >> fieldBase) + t4 + t13*1024 + t14*15632
		t4 = m & fieldBaseMask
		m = (m >> fieldBase) + t5 + t14*1024 + t15*15632
		t5 = m & fieldBaseMask
		m = (m >> fieldBase) + t6 + t15*1024 + t16*15632
		t6 = m & fieldBaseMask
		m = (m >> fieldBase) + t7 + t16*1024 + t17*15632
		t7 = m & fieldBaseMask
		m = (m >> fieldBase) + t8 + t17*1024 + t18*15632
		t8 = m & fieldBaseMask
		m = (m >> fieldBase) + t9 + t18*1024 + t19*68719492368
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
		n = t0 + m*977
		self.n[0] = n & fieldBaseMask
		n = (n >> fieldBase) + t1 + m*64
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
	def mulInt(self, val): # uint) *fieldVal {
		"""
		MulInt multiplies the field value by the passed int and stores the result in
		f.  Note that this function can overflow if multiplying the value by any of
		the individual words exceeds a max uint32.  Therefore it is important that
		the caller ensures no overflows will occur before using this function.
	
		The field value is returned to support chaining.  This enables syntax like:
		f.MulInt(2).Add(f2) so that f = 2 * f + f2.
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
		Mul multiplies the passed value to the existing field value and stores the
		result in f.  Note that this function can overflow if multiplying any
		of the individual words exceeds a max uint32.  In practice, this means the
		magnitude of either value involved in the multiplication must be a max of
		8.
		
		The field value is returned to support chaining.  This enables syntax like:
		f.Mul(f2).AddInt(1) so that f = (f * f2) + 1.
		"""
		return self.mul2(self, f)
	def mul2(self, val, val2): # val *fieldVal, val2 *fieldVal) *fieldVal {
		"""
		Mul2 multiplies the passed two field values together and stores the result
		result in f.  Note that this function can overflow if multiplying any of
		the individual words exceeds a max uint32.  In practice, this means the
		magnitude of either value involved in the multiplication must be a max of
		8.

		The field value is returned to support chaining.  This enables syntax like:
		f3.Mul2(f, f2).AddInt(1) so that f3 = (f * f2) + 1.
		"""
		# This could be done with a couple of for loops and an array to store
		# the intermediate terms, but this unrolled version is significantly
		# faster.

		# Terms for 2^(fieldBase*0).
		m = val.n[0] * val2.n[0]
		t0 = m & fieldBaseMask

		# Terms for 2^(fieldBase*1).
		m = (m >> fieldBase) + val.n[0]*val2.n[1] + val.n[1]*val2.n[0]
		t1 = m & fieldBaseMask

		# Terms for 2^(fieldBase*2).
		m = (m >> fieldBase) + val.n[0]*val2.n[2] + val.n[1]*val2.n[1] + val.n[2]*val2.n[0]
		t2 = m & fieldBaseMask

		# Terms for 2^(fieldBase*3).
		m = (m >> fieldBase) + val.n[0]*val2.n[3] + val.n[1]*val2.n[2] + val.n[2]*val2.n[1] + val.n[3]*val2.n[0]
		t3 = m & fieldBaseMask

		# Terms for 2^(fieldBase*4).
		m = (m >> fieldBase) + val.n[0]*val2.n[4] + val.n[1]*val2.n[3] + val.n[2]*val2.n[2] + val.n[3]*val2.n[1] + val.n[4]*val2.n[0]
		t4 = m & fieldBaseMask

		# Terms for 2^(fieldBase*5).
		m = (m >> fieldBase) + val.n[0]*val2.n[5] + val.n[1]*val2.n[4] + val.n[2]*val2.n[3] + val.n[3]*val2.n[2] + val.n[4]*val2.n[1] + val.n[5]*val2.n[0]
		t5 = m & fieldBaseMask

		# Terms for 2^(fieldBase*6).
		m = (m >> fieldBase) + val.n[0]*val2.n[6] + val.n[1]*val2.n[5] + val.n[2]*val2.n[4] + val.n[3]*val2.n[3] + val.n[4]*val2.n[2] + val.n[5]*val2.n[1] + val.n[6]*val2.n[0]
		t6 = m & fieldBaseMask

		# Terms for 2^(fieldBase*7).
		m = (m >> fieldBase) + val.n[0]*val2.n[7] + val.n[1]*val2.n[6] + val.n[2]*val2.n[5] + val.n[3]*val2.n[4] + val.n[4]*val2.n[3] + val.n[5]*val2.n[2] + val.n[6]*val2.n[1] + val.n[7]*val2.n[0]
		t7 = m & fieldBaseMask

		# Terms for 2^(fieldBase*8).
		m = (m >> fieldBase) + val.n[0]*val2.n[8] + val.n[1]*val2.n[7] + val.n[2]*val2.n[6] + val.n[3]*val2.n[5] + val.n[4]*val2.n[4] + val.n[5]*val2.n[3] + val.n[6]*val2.n[2] + val.n[7]*val2.n[1] + val.n[8]*val2.n[0]
		t8 = m & fieldBaseMask

		# Terms for 2^(fieldBase*9).
		m = (m >> fieldBase) + val.n[0]*val2.n[9] + val.n[1]*val2.n[8] + val.n[2]*val2.n[7] + val.n[3]*val2.n[6] + val.n[4]*val2.n[5] + val.n[5]*val2.n[4] + val.n[6]*val2.n[3] + val.n[7]*val2.n[2] + val.n[8]*val2.n[1] + val.n[9]*val2.n[0]
		t9 = m & fieldBaseMask

		# Terms for 2^(fieldBase*10).
		m = (m >> fieldBase) + val.n[1]*val2.n[9] + val.n[2]*val2.n[8] + val.n[3]*val2.n[7] + val.n[4]*val2.n[6] + val.n[5]*val2.n[5] + val.n[6]*val2.n[4] + val.n[7]*val2.n[3] + val.n[8]*val2.n[2] + val.n[9]*val2.n[1]
		t10 = m & fieldBaseMask

		# Terms for 2^(fieldBase*11).
		m = (m >> fieldBase) + val.n[2]*val2.n[9] + val.n[3]*val2.n[8] + val.n[4]*val2.n[7] + val.n[5]*val2.n[6] + val.n[6]*val2.n[5] + val.n[7]*val2.n[4] + val.n[8]*val2.n[3] + val.n[9]*val2.n[2]
		t11 = m & fieldBaseMask

		# Terms for 2^(fieldBase*12).
		m = (m >> fieldBase) + val.n[3]*val2.n[9] + val.n[4]*val2.n[8] + val.n[5]*val2.n[7] + val.n[6]*val2.n[6] + val.n[7]*val2.n[5] + val.n[8]*val2.n[4] + val.n[9]*val2.n[3]
		t12 = m & fieldBaseMask

		# Terms for 2^(fieldBase*13).
		m = (m >> fieldBase) + val.n[4]*val2.n[9] + val.n[5]*val2.n[8] + val.n[6]*val2.n[7] + val.n[7]*val2.n[6] + val.n[8]*val2.n[5] + val.n[9]*val2.n[4]
		t13 = m & fieldBaseMask

		# Terms for 2^(fieldBase*14).
		m = (m >> fieldBase) + val.n[5]*val2.n[9] + val.n[6]*val2.n[8] + val.n[7]*val2.n[7] + val.n[8]*val2.n[6] + val.n[9]*val2.n[5]
		t14 = m & fieldBaseMask

		# Terms for 2^(fieldBase*15).
		m = (m >> fieldBase) + val.n[6]*val2.n[9] + val.n[7]*val2.n[8] + val.n[8]*val2.n[7] + val.n[9]*val2.n[6]
		t15 = m & fieldBaseMask

		# Terms for 2^(fieldBase*16).
		m = (m >> fieldBase) + val.n[7]*val2.n[9] + val.n[8]*val2.n[8] + val.n[9]*val2.n[7]
		t16 = m & fieldBaseMask

		# Terms for 2^(fieldBase*17).
		m = (m >> fieldBase) + val.n[8]*val2.n[9] + val.n[9]*val2.n[8]
		t17 = m & fieldBaseMask

		# Terms for 2^(fieldBase*18).
		m = (m >> fieldBase) + val.n[9]*val2.n[9]
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
		m = t0 + t10*15632
		t0 = m & fieldBaseMask
		m = (m >> fieldBase) + t1 + t10*1024 + t11*15632
		t1 = m & fieldBaseMask
		m = (m >> fieldBase) + t2 + t11*1024 + t12*15632
		t2 = m & fieldBaseMask
		m = (m >> fieldBase) + t3 + t12*1024 + t13*15632
		t3 = m & fieldBaseMask
		m = (m >> fieldBase) + t4 + t13*1024 + t14*15632
		t4 = m & fieldBaseMask
		m = (m >> fieldBase) + t5 + t14*1024 + t15*15632
		t5 = m & fieldBaseMask
		m = (m >> fieldBase) + t6 + t15*1024 + t16*15632
		t6 = m & fieldBaseMask
		m = (m >> fieldBase) + t7 + t16*1024 + t17*15632
		t7 = m & fieldBaseMask
		m = (m >> fieldBase) + t8 + t17*1024 + t18*15632
		t8 = m & fieldBaseMask
		m = (m >> fieldBase) + t9 + t18*1024 + t19*68719492368
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
		d = t0 + m*977
		self.n[0] = d & fieldBaseMask
		d = (d >> fieldBase) + t1 + m*64
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
	def add2(self, val, val2): #val *fieldVal, val2 *fieldVal) *fieldVal {
		"""
		Add2 adds the passed two field values together and stores the result in f.
	
		The field value is returned to support chaining.  This enables syntax like:
		f3.Add2(f, f2).AddInt(1) so that f3 = f + f2 + 1.
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
		PutBytes unpacks the field value to a 32-byte big-endian value using the
		passed byte array.  There is a similar function, Bytes, which unpacks the
		field value into a new array and returns that.  This version is provided
		since it can be useful to cut down on the number of allocations by allowing
		the caller to reuse a buffer.
			
		The field value must be normalized for this function to return the correct
		result.
		"""
		# Unpack the 256 total bits from the 10 uint32 words with a max of
		# 26-bits per word.  This could be done with a couple of for loops,
		# but this unrolled version is a bit faster.  Benchmarks show this is
		# about 10 times faster than the variant which uses loops.
		f = self
		b[31] = f.n[0] & eightBitsMask
		b[30] = (f.n[0] >> 8) & eightBitsMask
		b[29] = (f.n[0] >> 16) & eightBitsMask
		b[28] = (f.n[0]>>24)&twoBitsMask | (f.n[1]&sixBitsMask)<<2
		b[27] = (f.n[1] >> 6) & eightBitsMask
		b[26] = (f.n[1] >> 14) & eightBitsMask
		b[25] = (f.n[1]>>22)&fourBitsMask | (f.n[2]&fourBitsMask)<<4
		b[24] = (f.n[2] >> 4) & eightBitsMask
		b[23] = (f.n[2] >> 12) & eightBitsMask
		b[22] = (f.n[2]>>20)&sixBitsMask | (f.n[3]&twoBitsMask)<<6
		b[21] = (f.n[3] >> 2) & eightBitsMask
		b[20] = (f.n[3] >> 10) & eightBitsMask
		b[19] = (f.n[3] >> 18) & eightBitsMask
		b[18] = f.n[4] & eightBitsMask
		b[17] = (f.n[4] >> 8) & eightBitsMask
		b[16] = (f.n[4] >> 16) & eightBitsMask
		b[15] = (f.n[4]>>24)&twoBitsMask | (f.n[5]&sixBitsMask)<<2
		b[14] = (f.n[5] >> 6) & eightBitsMask
		b[13] = (f.n[5] >> 14) & eightBitsMask
		b[12] = (f.n[5]>>22)&fourBitsMask | (f.n[6]&fourBitsMask)<<4
		b[11] = (f.n[6] >> 4) & eightBitsMask
		b[10] = (f.n[6] >> 12) & eightBitsMask
		b[9] = (f.n[6]>>20)&sixBitsMask | (f.n[7]&twoBitsMask)<<6
		b[8] = (f.n[7] >> 2) & eightBitsMask
		b[7] = (f.n[7] >> 10) & eightBitsMask
		b[6] = (f.n[7] >> 18) & eightBitsMask
		b[5] = f.n[8] & eightBitsMask
		b[4] = (f.n[8] >> 8) & eightBitsMask
		b[3] = (f.n[8] >> 16) & eightBitsMask
		b[2] = (f.n[8]>>24)&twoBitsMask | (f.n[9]&sixBitsMask)<<2
		b[1] = (f.n[9] >> 6) & eightBitsMask
		b[0] = (f.n[9] >> 14) & eightBitsMask
	def bytes(self):
		"""
		Bytes unpacks the field value to a 32-byte big-endian value.  See PutBytes
		for a variant that allows the a buffer to be passed which can be useful to
		to cut down on the number of allocations by allowing the caller to reuse a
		buffer.
				
		The field value must be normalized for this function to return correct
		result.
		"""
		b = ByteArray(0, length=32)
		self.putBytes(b)
		return b
	def string(self):
		"""  String returns the field value as a human-readable hex string."""
		f = FieldVal().set(self).normalize()
		return f.bytes().hex()

BytePoints = []

def loadS256BytePoints():
	if len(secp256k1BytePoints) == 0:
		raise Exception("basepoint string empty")

	# Decompress the pre-computed table used to accelerate scalar base
	# multiplication.
	compressed = b64decode(secp256k1BytePoints)
	serialized = zdecompress(compressed)

	# Deserialize the precomputed byte points and set the curve to them.
	offset = 0
	# var bytePoints [32][256][3]fieldVal
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
				px.n[j] = serialized[offset+3:offset-1:-1]
				offset += 4
			for j in range(10):
				py.n[j] = serialized[offset+3:offset-1:-1]
				offset += 4
			for j in range(10):
				pz.n[j] = serialized[offset+3:offset-1:-1]
				offset += 4

loadS256BytePoints()

class TestField(unittest.TestCase):
	def test_set_int(self):
		"""
		TestSetInt ensures that setting a field value to various native integers
		works as expected.
		"""
		tests = [
			(5, [5, 0, 0, 0, 0, 0, 0, 0, 0, 0]), # 2^26
			(67108864, [67108864, 0, 0, 0, 0, 0, 0, 0, 0, 0]), # 2^26
			(67108865, [67108865, 0, 0, 0, 0, 0, 0, 0, 0, 0]), # 2^26 + 1
			(4294967295, [4294967295, 0, 0, 0, 0, 0, 0, 0, 0, 0]), # 2^32 - 1
		]

		print("Running %d tests" % len(tests))
		for i, v in tests:
			f = FieldVal()
			f.setInt(i)
			self.assertListEqual(v, f.n)
	def test_zero(self):
		"""TestZero ensures that zeroing a field value zero works as expected."""
		f = FieldVal()
		f.setInt(2)
		f.zero()
		self.assertTrue(all((x == 0 for x in f.n)))
	def test_is_zero(self):
		"""TestIsZero ensures that checking if a field IsZero works as expected."""
		f = FieldVal()
		self.assertTrue(f.isZero())

		f.setInt(1)
		self.assertFalse(f.isZero())

		f.zero()
		self.assertTrue(f.isZero())
	def test_normalize(self):
		"""
		TestNormalize ensures that normalizing the internal field words works as
		expected.
		"""
		tests = [
			[ # 0
				[0x00000005, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				[0x00000005, 0, 0, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^26
			[ # 1
				[0x04000000, 0x0, 0, 0, 0, 0, 0, 0, 0, 0],
				[0x00000000, 0x1, 0, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^26 + 1
			[ # 2
				[0x04000001, 0x0, 0, 0, 0, 0, 0, 0, 0, 0],
				[0x00000001, 0x1, 0, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^32 - 1
			[ # 3
				[0xffffffff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
				[0x03ffffff, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^32
			[ # 4
				[0x04000000, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0],
				[0x00000000, 0x40, 0, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^32 + 1
			[ # 5
				[0x04000001, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0],
				[0x00000001, 0x40, 0, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^64 - 1
			[ # 6
				[0xffffffff, 0xffffffc0, 0xfc0, 0, 0, 0, 0, 0, 0, 0],
				[0x03ffffff, 0x03ffffff, 0xfff, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^64
			[ # 7
				[0x04000000, 0x03ffffff, 0x0fff, 0, 0, 0, 0, 0, 0, 0],
				[0x00000000, 0x00000000, 0x1000, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^64 + 1
			[ # 8
				[0x04000001, 0x03ffffff, 0x0fff, 0, 0, 0, 0, 0, 0, 0],
				[0x00000001, 0x00000000, 0x1000, 0, 0, 0, 0, 0, 0, 0],
			],
			# 2^96 - 1
			[ # 9
				[0xffffffff, 0xffffffc0, 0xffffffc0, 0x3ffc0, 0, 0, 0, 0, 0, 0],
				[0x03ffffff, 0x03ffffff, 0x03ffffff, 0x3ffff, 0, 0, 0, 0, 0, 0],
			],
			# 2^96
			[ # 10
				[0x04000000, 0x03ffffff, 0x03ffffff, 0x3ffff, 0, 0, 0, 0, 0, 0],
				[0x00000000, 0x00000000, 0x00000000, 0x40000, 0, 0, 0, 0, 0, 0],
			],
			# 2^128 - 1
			[ # 11
				[0xffffffff, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffc0, 0, 0, 0, 0, 0],
				[0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0xffffff, 0, 0, 0, 0, 0],
			],
			# 2^128
			[ # 12
				[0x04000000, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x0ffffff, 0, 0, 0, 0, 0],
				[0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x1000000, 0, 0, 0, 0, 0],
			],
			# 2^256 - 4294968273 (secp256k1 prime)
			[ # 13
				[0xfffffc2f, 0xffffff80, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0x3fffc0],
				[0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x000000],
			],
			# Prime larger than P where both first and second words are larger
			# than P's first and second words
			[ # 14
				[0xfffffc30, 0xffffff86, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0x3fffc0],
				[0x00000001, 0x00000006, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x000000],
			],
			# Prime larger than P where only the second word is larger
			# than P's second words.
			[ # 15
				[0xfffffc2a, 0xffffff87, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0x3fffc0],
				[0x03fffffb, 0x00000006, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x000000],
			],
			# 2^256 - 1
			[ # 16
				[0xffffffff, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0xffffffc0, 0x3fffc0],
				[0x000003d0, 0x00000040, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x000000],
			],
			# Prime with field representation such that the initial
			# reduction does not result in a carry to bit 256.
			#
			# 2^256 - 4294968273 (secp256k1 prime)
			[ # 17
				[0x03fffc2f, 0x03ffffbf, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x003fffff],
				[0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
			],
			# Prime larger than P that reduces to a value which is still
			# larger than P when it has a magnitude of 1 due to its first
			# word and does not result in a carry to bit 256.
			#
			# 2^256 - 4294968272 (secp256k1 prime + 1)
			[ # 18
				[0x03fffc30, 0x03ffffbf, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x003fffff],
				[0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
			],
			# Prime larger than P that reduces to a value which is still
			# larger than P when it has a magnitude of 1 due to its second
			# word and does not result in a carry to bit 256.
			#
			# 2^256 - 4227859409 (secp256k1 prime + 0x4000000)
			[ # 19
				[0x03fffc2f, 0x03ffffc0, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x003fffff],
				[0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
			],
			# Prime larger than P that reduces to a value which is still
			# larger than P when it has a magnitude of 1 due to a carry to
			# bit 256, but would not be without the carry.  These values
			# come from the fact that P is 2^256 - 4294968273 and 977 is
			# the low order word in the internal field representation.
			#
			# 2^256 * 5 - ((4294968273 - (977+1)) * 4)
			[ # 20
				[0x03ffffff, 0x03fffeff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x0013fffff],
				[0x00001314, 0x00000040, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x000000000],
			],
			# Prime larger than P that reduces to a value which is still
			# larger than P when it has a magnitude of 1 due to both a
			# carry to bit 256 and the first word.
			[ # 21
				[0x03fffc30, 0x03ffffbf, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x07ffffff, 0x003fffff],
				[0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001],
			],
			# Prime larger than P that reduces to a value which is still
			# larger than P when it has a magnitude of 1 due to both a
			# carry to bit 256 and the second word.
			#
			[ # 22
				[0x03fffc2f, 0x03ffffc0, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x3ffffff, 0x07ffffff, 0x003fffff],
				[0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000000, 0x00000000, 0x00000001],
			],
			# Prime larger than P that reduces to a value which is still
			# larger than P when it has a magnitude of 1 due to a carry to
			# bit 256 and the first and second words.
			#
			[ # 23
				[0x03fffc30, 0x03ffffc0, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff, 0x07ffffff, 0x003fffff],
				[0x00000001, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001],
			],
		]

		for i, (raw, normalized) in enumerate(tests):
			f = FieldVal()
			f.n = raw
			f.normalize()
			self.assertListEqual(normalized, f.n, msg="test %i" % i)
	def test_equals(self):
		"""
		TestEquals ensures that checking two field values for equality via Equals
		works as expected.
		"""
		tests = [
			("0", "0", True),
			("0", "1", False),
			("1", "0", False),
			# 2^32 - 1 == 2^32 - 1?
			("ffffffff", "ffffffff", True),
			# 2^64 - 1 == 2^64 - 2?
			("ffffffffffffffff", "fffffffffffffffe", False),
			# 0 == prime (mod prime)?
			("0", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", True),
			# 1 == prime+1 (mod prime)?
			("1", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30", True),
		]
		for i, (a, b, eq) in enumerate(tests):
			fa = FieldVal.fromHex(a).normalize()
			fb = FieldVal.fromHex(b).normalize()
			self.assertEqual(fa.equals(fb), eq, msg="test %i" % i)
	def test_negate(self):
		"""TestNegate ensures that negating field values via Negate works as expected."""
		tests = [
			# secp256k1 prime (aka 0)
			("0", "0"),
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "0"),
			("0", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
			# secp256k1 prime-1
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", "1"),
			("1", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"),
			# secp256k1 prime-2
			("2", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d"),
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d", "2"),
			# Random sampling
			(
				"b3d9aac9c5e43910b4385b53c7e78c21d4cd5f8e683c633aed04c233efc2e120",
				"4c2655363a1bc6ef4bc7a4ac381873de2b32a07197c39cc512fb3dcb103d1b0f",
			),
			(
				"f8a85984fee5a12a7c8dd08830d83423c937d77c379e4a958e447a25f407733f",
				"757a67b011a5ed583722f77cf27cbdc36c82883c861b56a71bb85d90bf888f0",
			),
			(
				"45ee6142a7fda884211e93352ed6cb2807800e419533be723a9548823ece8312",
				"ba119ebd5802577bdee16ccad12934d7f87ff1be6acc418dc56ab77cc131791d",
			),
			(
				"53c2a668f07e411a2e473e1c3b6dcb495dec1227af27673761d44afe5b43d22b",
				"ac3d59970f81bee5d1b8c1e3c49234b6a213edd850d898c89e2bb500a4bc2a04",
			),
		]

		for i, (a, b) in enumerate(tests):
			fa = FieldVal.fromHex(a).normalize().negate(1).normalize()
			fb = FieldVal.fromHex(b).normalize()
			self.assertTrue(fa.equals(fb), msg="test %i" % i)
	def test_add(self):
		""" TestAdd ensures that adding two field values together via Add works as expected."""
		tests = [
			("0", "1", "1"),
			("1", "0", "1"),
			("1", "1", "2"),
			# secp256k1 prime-1 + 1
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", "1", "0"),
			# secp256k1 prime + 1
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "1", "1"),
			# Random samples.
			(
				"2b2012f975404e5065b4292fb8bed0a5d315eacf24c74d8b27e73bcc5430edcc",
				"2c3cefa4e4753e8aeec6ac4c12d99da4d78accefda3b7885d4c6bab46c86db92",
				"575d029e59b58cdb547ad57bcb986e4aaaa0b7beff02c610fcadf680c0b7c95e",
			),
			(
				"8131e8722fe59bb189692b96c9f38de92885730f1dd39ab025daffb94c97f79c",
				"ff5454b765f0aab5f0977dcc629becc84cabeb9def48e79c6aadb2622c490fa9",
				"80863d2995d646677a00a9632c8f7ab175315ead0d1c824c9088b21c78e10b16",
			),
			(
				"c7c95e93d0892b2b2cdd77e80eb646ea61be7a30ac7e097e9f843af73fad5c22",
				"3afe6f91a74dfc1c7f15c34907ee981656c37236d946767dd53ccad9190e437c",
				"02c7ce2577d72747abf33b3116a4df00b881ec6785c47ffc74c105d158bba36f",
			),
			(
				"fd1c26f6a23381e5d785ba889494ec059369b888ad8431cd67d8c934b580dbe1",
				"a475aa5a31dcca90ef5b53c097d9133d6b7117474b41e7877bb199590fc0489c",
				"a191d150d4104c76c6e10e492c6dff42fedacfcff8c61954e38a628ec541284e",
			),
		]

		for i, (a, b, res) in enumerate(tests):
			fa = FieldVal.fromHex(a).normalize()
			fb = FieldVal.fromHex(b).normalize()
			fres = FieldVal.fromHex(res).normalize()
			result = fa.add(fb).normalize()
			self.assertTrue(fres.equals(result), msg="test %i" % i)
	def test_add2(self):
		""" TestAdd2 ensures that adding two field values together via Add2 works as expected."""
		tests = [
			("0", "1", "1"),
			("1", "0", "1"),
			("1", "1", "2"),
			# secp256k1 prime-1 + 1
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", "1", "0"),
			# secp256k1 prime + 1
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "1", "1"),
			# close but over the secp256k1 prime
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000", "f1ffff000", "1ffff3d1"),
			# Random samples.
			(
				"ad82b8d1cc136e23e9fd77fe2c7db1fe5a2ecbfcbde59ab3529758334f862d28",
				"4d6a4e95d6d61f4f46b528bebe152d408fd741157a28f415639347a84f6f574b",
				"faed0767a2e98d7330b2a0bcea92df3eea060d12380e8ec8b62a9fdb9ef58473",
			),
			(
				"f3f43a2540054a86e1df98547ec1c0e157b193e5350fb4a3c3ea214b228ac5e7",
				"25706572592690ea3ddc951a1b48b504a4c83dc253756e1b96d56fdfb3199522",
				"19649f97992bdb711fbc2d6e9a0a75e5fc79d1a7888522bf5abf912bd5a45eda",
			),
			(
				"6915bb94eef13ff1bb9b2633d997e13b9b1157c713363cc0e891416d6734f5b8",
				"11f90d6ac6fe1c4e8900b1c85fb575c251ec31b9bc34b35ada0aea1c21eded22",
				"7b0ec8ffb5ef5c40449bd7fc394d56fdecfd8980cf6af01bc29c2b898922e2da",
			),
			(
				"48b0c9eae622eed9335b747968544eb3e75cb2dc8128388f948aa30f88cabde4",
				"0989882b52f85f9d524a3a3061a0e01f46d597839d2ba637320f4b9510c8d2d5",
				"523a5216391b4e7685a5aea9c9f52ed32e324a601e53dec6c699eea4999390b9",
			),
		]

		for i, (a, b, res) in enumerate(tests):
			fa = FieldVal.fromHex(a).normalize()
			fb = FieldVal.fromHex(b).normalize()
			fres = FieldVal.fromHex(res).normalize()
			result = fa.add2(fa, fb).normalize()
			self.assertTrue(fres.equals(result), msg="test %i" % i)
	def test_mul(self):
		""" TestMul ensures that multiplying two field valuess via Mul works as expected."""
		tests = [
			("0", "0", "0"),
			("1", "0", "0"),
			("0", "1", "0"),
			("1", "1", "1"),
			# slightly over prime
			(
				"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff1ffff",
				"1000",
				"1ffff3d1",
			),
			# secp256k1 prime-1 * 2
			(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
				"2",
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
			),
			# secp256k1 prime * 3
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "3", "0"),
			# secp256k1 prime-1 * 8
			(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
				"8",
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc27",
			),
			# Random samples.
			(
				"cfb81753d5ef499a98ecc04c62cb7768c2e4f1740032946db1c12e405248137e",
				"58f355ad27b4d75fb7db0442452e732c436c1f7c5a7c4e214fa9cc031426a7d3",
				"1018cd2d7c2535235b71e18db9cd98027386328d2fa6a14b36ec663c4c87282b",
			),
			(
				"26e9d61d1cdf3920e9928e85fa3df3e7556ef9ab1d14ec56d8b4fc8ed37235bf",
				"2dfc4bbe537afee979c644f8c97b31e58be5296d6dbc460091eae630c98511cf",
				"da85f48da2dc371e223a1ae63bd30b7e7ee45ae9b189ac43ff357e9ef8cf107a",
			),
			(
				"5db64ed5afb71646c8b231585d5b2bf7e628590154e0854c4c29920b999ff351",
				"279cfae5eea5d09ade8e6a7409182f9de40981bc31c84c3d3dfe1d933f152e9a",
				"2c78fbae91792dd0b157abe3054920049b1879a7cc9d98cfda927d83be411b37",
			),
			(
				"b66dfc1f96820b07d2bdbd559c19319a3a73c97ceb7b3d662f4fe75ecb6819e6",
				"bf774aba43e3e49eb63a6e18037d1118152568f1a3ac4ec8b89aeb6ff8008ae1",
				"c4f016558ca8e950c21c3f7fc15f640293a979c7b01754ee7f8b3340d4902ebb",
			),
		]

		for i, (a, b, res) in enumerate(tests):
			fa = FieldVal.fromHex(a).normalize()
			fb = FieldVal.fromHex(b).normalize()
			fres = FieldVal.fromHex(res).normalize()
			result = fa.mul(fb).normalize()
			self.assertTrue(fres.equals(result), msg="test %i" % i)
	def test_square(self):
		""" TestSquare ensures that squaring field values via Square works as expected."""
		tests = [
			# secp256k1 prime (aka 0)
			("0", "0"),
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "0"),
			("0", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
			# secp256k1 prime-1
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", "1"),
			# secp256k1 prime-2
			("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d", "4"),
			# Random sampling
			(
				"b0ba920360ea8436a216128047aab9766d8faf468895eb5090fc8241ec758896",
				"133896b0b69fda8ce9f648b9a3af38f345290c9eea3cbd35bafcadf7c34653d3",
			),
			(
				"c55d0d730b1d0285a1599995938b042a756e6e8857d390165ffab480af61cbd5",
				"cd81758b3f5877cbe7e5b0a10cebfa73bcbf0957ca6453e63ee8954ab7780bee",
			),
			(
				"e89c1f9a70d93651a1ba4bca5b78658f00de65a66014a25544d3365b0ab82324",
				"39ffc7a43e5dbef78fd5d0354fb82c6d34f5a08735e34df29da14665b43aa1f",
			),
			(
				"7dc26186079d22bcbe1614aa20ae627e62d72f9be7ad1e99cac0feb438956f05",
				"bf86bcfc4edb3d81f916853adfda80c07c57745b008b60f560b1912f95bce8ae",
			),
		]

		for i, (a, res) in enumerate(tests):
			f = FieldVal.fromHex(a).normalize().square().normalize()
			expected = FieldVal.fromHex(res).normalize()
			self.assertTrue(f.equals(expected), msg="test %i" % i)
	def test_string(self):
		""" TestStringer ensures the stringer returns the appropriate hex string."""
		tests = [
			("0", "0000000000000000000000000000000000000000000000000000000000000000"),
			("1", "0000000000000000000000000000000000000000000000000000000000000001"),
			("a", "000000000000000000000000000000000000000000000000000000000000000a"),
			("b", "000000000000000000000000000000000000000000000000000000000000000b"),
			("c", "000000000000000000000000000000000000000000000000000000000000000c"),
			("d", "000000000000000000000000000000000000000000000000000000000000000d"),
			("e", "000000000000000000000000000000000000000000000000000000000000000e"),
			("f", "000000000000000000000000000000000000000000000000000000000000000f"),
			("f0", "00000000000000000000000000000000000000000000000000000000000000f0"),
			# 2^26-1
			(
				"3ffffff",
				"0000000000000000000000000000000000000000000000000000000003ffffff",
			),
			# 2^32-1
			(
				"ffffffff",
				"00000000000000000000000000000000000000000000000000000000ffffffff",
			),
			# 2^64-1
			(
				"ffffffffffffffff",
				"000000000000000000000000000000000000000000000000ffffffffffffffff",
			),
			# 2^96-1
			(
				"ffffffffffffffffffffffff",
				"0000000000000000000000000000000000000000ffffffffffffffffffffffff",
			),
			# 2^128-1
			(
				"ffffffffffffffffffffffffffffffff",
				"00000000000000000000000000000000ffffffffffffffffffffffffffffffff",
			),
			# 2^160-1
			(
				"ffffffffffffffffffffffffffffffffffffffff",
				"000000000000000000000000ffffffffffffffffffffffffffffffffffffffff",
			),
			# 2^192-1
			(
				"ffffffffffffffffffffffffffffffffffffffffffffffff",
				"0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff",
			),
			# 2^224-1
			(
				"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			),
			# 2^256-4294968273 (the secp256k1 prime, so should result in 0)
			(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
				"0000000000000000000000000000000000000000000000000000000000000000",
			),
			# 2^256-4294968274 (the secp256k1 prime+1, so should result in 1)
			(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
				"0000000000000000000000000000000000000000000000000000000000000001",
			),

			# # Invalid hex
			# these are silently converted in go, but allowed to raise an exception in Python
			# ("g", "0000000000000000000000000000000000000000000000000000000000000000"),
			# ("1h", "0000000000000000000000000000000000000000000000000000000000000000"),
			# ("i1", "0000000000000000000000000000000000000000000000000000000000000000"),
		]

		for i, (a, res) in enumerate(tests):
			f = FieldVal.fromHex(a)
			self.assertEqual(res, f.string(), msg="test %i" % i)
