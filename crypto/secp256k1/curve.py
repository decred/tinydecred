from tinydecred.crypto.secp256k1.field import FieldVal, BytePoints
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.crypto.rando import generateSeed
import unittest

COORDINATE_LEN = 32
PUBKEY_COMPRESSED_LEN = COORDINATE_LEN + 1
PUBKEY_LEN = 65
PUBKEY_COMPRESSED  = 0x02 # 0x02 y_bit + x coord
PUBKEY_UNCOMPRESSED = 0x04 # 0x04 x coord + y coord

fieldOne = FieldVal.fromInt(1)

def isEven(i):
	return i % 2 == 0

def NAF(k):
	"""
	NAF takes a positive integer k and returns the Non-Adjacent Form (NAF) as two
	byte slices.  The first is where 1s will be.  The second is where -1s will
	be.  NAF is convenient in that on average, only 1/3rd of its values are
	non-zero.  This is algorithm 3.30 from [GECC].
	
	Essentially, this makes it possible to minimize the number of operations
	since the resulting ints returned will be at least 50% 0s.
	The essence of this algorithm is that whenever we have consecutive 1s
	in the binary, we want to put a -1 in the lowest bit and get a bunch
	of 0s up to the highest bit of consecutive 1s.  This is due to this
	identity:
	2^n + 2^(n-1) + 2^(n-2) + ... + 2^(n-k) = 2^(n+1) - 2^(n-k)
	
	The algorithm thus may need to go 1 more bit than the length of the
	bits we actually have, hence bits being 1 bit longer than was
	necessary.  Since we need to know whether adding will cause a carry,
	we go from right-to-left in this addition.
	"""
	carry, curIsOne, nextIsOne = False, False, False
	# these default to zero
	retPos  = ByteArray(0, length=len(k)+1)
	retNeg  = ByteArray(0, length=len(k)+1)
	for i in range(len(k)-1, -1, -1):
		curByte = k[i]
		for j in range(8):
			curIsOne = curByte&1 == 1
			if j == 7:
				if i == 0:
					nextIsOne = False
				else:
					nextIsOne = k[i-1]&1 == 1
			else:
				nextIsOne = curByte&2 == 2
			if carry:
				if curIsOne:
					# This bit is 1, so continue to carry
					# and don't need to do anything.
					pass
				else:
					# We've hit a 0 after some number of 1s.
					if nextIsOne:
						# Start carrying again since
						# a new sequence of 1s is
						# starting.
						retNeg[i+1] += 1 << j
					else:
						# Stop carrying since 1s have
						# stopped.
						carry = False
						retPos[i+1] += 1 << j
			elif curIsOne:
				if nextIsOne:
					# If this is the start of at least 2
					# consecutive 1s, set the current one
					# to -1 and start carrying.
					retNeg[i+1] += 1 << j
					carry = True
				else:
					# This is a singleton, not consecutive
					# 1s.
					retPos[i+1] += 1 << j
			curByte >>= 1
	if carry:
		retPos[0] = 1
		return retPos, retNeg
	return retPos[1:], retNeg[1:]

class PublicKey:
	def __init__(self, curve, x, y):
		self.curve = curve
		self.x = x
		self.y = y
	def serializeCompressed(self):
		fmt = PUBKEY_COMPRESSED
		if not isEven(self.y):
			fmt |= 0x1
		b = ByteArray(fmt)
		b += ByteArray(self.x, length=COORDINATE_LEN)
		assert len(b) == PUBKEY_COMPRESSED_LEN
		return b
	def serializeUncompressed(self):
		"""
		SerializeUncompressed serializes a public key in a 65-byte uncompressed
		format.
		"""
		b = ByteArray(PUBKEY_UNCOMPRESSED)
		b += ByteArray(self.x, length=32)
		b += ByteArray(self.y, length=32)
		return b

class PrivateKey:
	def __init__(self, curve, k, x, y):
		self.key = k
		self.pub = PublicKey(curve, x, y)

def randFieldElement(): # c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	"""
	randFieldElement returns a random element of the field underlying the given
	curve using the procedure given in [NSA] A.2.1.
	"""
	b = ByteArray(generateSeed(curve.BitSize//8+8))
	n = curve.N - 1
	k = b.int()
	k = k % n
	k = k + 1
	return k

def generateKey(): # (*PrivateKey, error) {
	""" GenerateKey generates a public and private key pair."""
	k = randFieldElement()
	x, y = curve.scalarBaseMult(k)
	return PrivateKey(curve, k, x, y)

class KoblitzCurve:

	def __init__(self, P, N, B, Gx, Gy, BitSize, H, q, byteSize, lamda, beta, a1, b1, a2, b2):
		self.P = P
		self.N = N
		self.B = B
		self.Gx = Gx
		self.Gy = Gy
		self.BitSize = BitSize
		self.H = H
		self.q = q
		self.byteSize = byteSize
		self.lamda = lamda
		self.beta = beta
		self.a1 = a1
		self.b1 = b1
		self.a2 = a2
		self.b2 = b2

	def scalarBaseMult(self, k): # []byte) (*big.Int, *big.Int) {
		"""
		ScalarBaseMult returns k*G where G is the base point of the group and k is a
		big endian integer.
		Part of the elliptic.Curve interface.
		"""
	# 	newK := curve.moduloReduce(k)
	# 	diff := len(curve.bytePoints) - len(newK)
		kb = ByteArray(k % self.N)
		diff = len(BytePoints) - len(kb)


	# 	// Point Q = ∞ (point at infinity).
	# 	qx, qy, qz := new(fieldVal), new(fieldVal), new(fieldVal)
		qx, qy, qz = FieldVal(), FieldVal(), FieldVal()

		# curve.bytePoints has all 256 byte points for each 8-bit window. The
		# strategy is to add up the byte points. This is best understood by
		# expressing k in base-256 which it already sort of is.
		# Each "digit" in the 8-bit window can be looked up using bytePoints
		# and added together.
		for i, bidx in enumerate(kb.b):
			p = BytePoints[diff+i][bidx]
			self.addJacobian(qx, qy, qz, p[0], p[1], p[2], qx, qy, qz)
		return self.fieldJacobianToBigAffine(qx, qy, qz)
	def splitK(self, k):
		"""
		splitK returns a balanced length-two representation of k and their signs.
		This is algorithm 3.74 from [GECC].
		
		One thing of note about this algorithm is that no matter what c1 and c2 are,
		the final equation of k = k1 + k2 * lambda (mod n) will hold.  This is
		provable mathematically due to how a1/b1/a2/b2 are computed.
		c1 and c2 are chosen to minimize the max(k1,k2).
		"""
		# At some point, it might be useful to write something similar to
		# fieldVal but for N instead of P as the prime field if this ends up
		# being a bottleneck.
		# c1 = round(b2 * k / n) from step 4.
		# Rounding isn't really necessary and costs too much, hence skipped
		c1 = (self.b2 + k) // self.N
		# c2 = round(b1 * k / n) from step 4 (sign reversed to optimize one step)
		# Rounding isn't really necessary and costs too much, hence skipped
		c2 = (self.b1 + k) // self.N
		# k1 = k - c1 * a1 - c2 * a2 from step 5 (note c2's sign is reversed)
		tmp1 = c1 * self.a1
		tmp2 = c2 * self.a2
		k1 = k - tmp1 + tmp2
		# k2 = - c1 * b1 - c2 * b2 from step 5 (note c2's sign is reversed)
		tmp1 = c1 * self.b1
		tmp2 = c2 * self.b2
		k2 = tmp2 - tmp1

		# Note Bytes() throws out the sign of k1 and k2. This matters
		# since k1 and/or k2 can be negative. Hence, we pass that
		# back separately.
		return k1, k2
	def scalarMult(self, Bx, By, k): #(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
		"""
		ScalarMult returns k*(Bx, By) where k is a big endian integer.
		Part of the elliptic.Curve interface.
		"""
		# Point Q = ∞ (point at infinity).
		fv = FieldVal
		qx, qy, qz = fv(), fv(), fv()

		# Decompose K into k1 and k2 in order to halve the number of EC ops.
		# See Algorithm 3.74 in [GECC].
		k1, k2 = self.splitK(k % self.N)

		# The main equation here to remember is:
		#   k * P = k1 * P + k2 * ϕ(P)
		#
		# P1 below is P in the equation, P2 below is ϕ(P) in the equation
		p1x, p1y = curve.bigAffineToField(Bx, By)
		p1yNeg = fv().negateVal(p1y, 1)
		p1z = fv().setInt(1)

		# NOTE: ϕ(x,y) = (βx,y).  The Jacobian z coordinate is 1, so this math
		# goes through.
		p2x = fv().mul2(p1x, curve.beta)
		p2y = fv().set(p1y)
		p2yNeg = fv().negateVal(p2y, 1)
		p2z = fv().setInt(1)

		# Flip the positive and negative values of the points as needed
		# depending on the signs of k1 and k2.  As mentioned in the equation
		# above, each of k1 and k2 are multiplied by the respective point.
		# Since -k * P is the same thing as k * -P, and the group law for
		# elliptic curves states that P(x, y) = -P(x, -y), it's faster and
		# simplifies the code to just make the point negative.
		if k1 < 0:
			p1y, p1yNeg = p1yNeg, p1y
		if k2 < 1:
			p2y, p2yNeg = p2yNeg, p2y

		# NAF versions of k1 and k2 should have a lot more zeros.
		#
		# The Pos version of the bytes contain the +1s and the Neg versions
		# contain the -1s.
		k1PosNAF, k1NegNAF = NAF(ByteArray(k1))
		k2PosNAF, k2NegNAF = NAF(ByteArray(k2))
		k1Len = len(k1PosNAF)
		k2Len = len(k2PosNAF)

		m = k1Len
		if m < k2Len:
			m = k2Len

		# Add left-to-right using the NAF optimization.  See algorithm 3.77
		# from [GECC].  This should be faster overall since there will be a lot
		# more instances of 0, hence reducing the number of Jacobian additions
		# at the cost of 1 possible extra doubling.
		for i in range(m):
			# Since we're going left-to-right, pad the front with 0s.
			if i < m-k1Len:
				k1BytePos = 0
				k1ByteNeg = 0
			else:
				k1BytePos = k1PosNAF[i-(m-k1Len)]
				k1ByteNeg = k1NegNAF[i-(m-k1Len)]
			if i < m-k2Len:
				k2BytePos = 0
				k2ByteNeg = 0
			else:
				k2BytePos = k2PosNAF[i-(m-k2Len)]
				k2ByteNeg = k2NegNAF[i-(m-k2Len)]

			for j in range(7, -1, -1):
				# Q = 2 * Q
				curve.doubleJacobian(qx, qy, qz, qx, qy, qz)

				if k1BytePos&0x80 == 0x80:
					curve.addJacobian(qx, qy, qz, p1x, p1y, p1z, qx, qy, qz)
				elif k1ByteNeg&0x80 == 0x80:
					curve.addJacobian(qx, qy, qz, p1x, p1yNeg, p1z, qx, qy, qz)

				if k2BytePos&0x80 == 0x80:
					curve.addJacobian(qx, qy, qz, p2x, p2y, p2z, qx, qy, qz)
				elif k2ByteNeg&0x80 == 0x80:
					curve.addJacobian(qx, qy, qz, p2x, p2yNeg, p2z, qx, qy, qz)
				k1BytePos = k1BytePos << 1
				k1ByteNeg = k1ByteNeg << 1
				k2BytePos = k2BytePos << 1
				k2ByteNeg = k2ByteNeg << 1

		# Convert the Jacobian coordinate field values back to affine big.Ints.
		return curve.fieldJacobianToBigAffine(qx, qy, qz)
	def publicKey(self, k):
		"""
		Create a public key from integer private key k.
		"""
		x, y = self.scalarBaseMult(k)
		return PublicKey(self, x, y)
	def parsePubKey(self, pubKeyStr):
		"""
		# ParsePubKey parses a public key for a koblitz curve from a bytestring into a
		# ecdsa.Publickey, verifying that it is valid. It supports compressed and
		# uncompressed signature formats, but not the hybrid format.
		"""
		if len(pubKeyStr) == 0:
			raise Exception("empty pubkey string")

		fmt = pubKeyStr[0]
		ybit = (fmt & 0x1) == 0x1
		fmt &= 0xff^0x01

		ifunc = lambda b: int.from_bytes(b, byteorder="big")

		pkLen = len(pubKeyStr)
		if pkLen == PUBKEY_LEN:
			if PUBKEY_UNCOMPRESSED != fmt:
				raise Exception("invalid magic in pubkey str: %d" % pubKeyStr[0])
			x = ifunc(pubKeyStr[1:33])
			y = ifunc(pubKeyStr[33:])

		elif pkLen == PUBKEY_COMPRESSED_LEN:
			# format is 0x2 | solution, <X coordinate>
			# solution determines which solution of the curve we use.
			#/ y^2 = x^3 + Curve.B
			if PUBKEY_COMPRESSED != fmt: 
				raise Exception("invalid magic in compressed pubkey string: %d" % pubKeyStr[0])
			x = ifunc(pubKeyStr[1:33])
			y = self.decompressPoint(x, ybit)
		else: # wrong!
			raise Exception("invalid pub key length %d" % len(pubKeyStr))

		if x > self.P:
			raise Exception("pubkey X parameter is >= to P")
		if y > self.P:
			raise Exception("pubkey Y parameter is >= to P")
		if not self.isAffineOnCurve(x, y):
			raise Exception("pubkey [%d, %d] isn't on secp256k1 curve" % (x, y))
		return PublicKey(self, x, y)
	def decompressPoint(self, x, ybit):
		"""
		decompressPoint decompresses a point on the given curve given the X point and
		the solution to use.
		"""
		# TODO(oga) This will probably only work for secp256k1 due to
		# optimizations.
		# Y = +-sqrt(x^3 + B)
		x3 = x**3 + self.B

		# now calculate sqrt mod p of x2 + B
		# This code used to do a full sqrt based on tonelli/shanks,
		# but this was replaced by the algorithms referenced in
		# https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
		y = pow(x3, self.q, self.P) #(x3**self.q) % self.P

		if ybit == isEven(y):
			y = self.P - y
		if ybit == isEven(y):
			raise Exception("ybit doesn't match oddnes")
		return y

	def addJacobian(self, x1, y1, z1, x2, y2, z2, x3, y3, z3): # *fieldVal) {
		"""
		addJacobian adds the passed Jacobian points (x1, y1, z1) and (x2, y2, z2)
		together and stores the result in (x3, y3, z3).
		"""
		# A point at infinity is the identity according to the group law for
		# elliptic curve cryptography.  Thus, ∞ + P = P and P + ∞ = P.
		if (x1.isZero() and y1.isZero()) or z1.isZero():
			x3.set(x2)
			y3.set(y2)
			z3.set(z2)
			return
		if (x2.isZero() and y2.isZero()) or z2.isZero():
			x3.set(x1)
			y3.set(y1)
			z3.set(z1)
			return
		# Faster point addition can be achieved when certain assumptions are
		# met.  For example, when both points have the same z value, arithmetic
		# on the z values can be avoided.  This section thus checks for these
		# conditions and calls an appropriate add function which is accelerated
		# by using those assumptions.
		z1.normalize()
		z2.normalize()
		isZ1One = z1.equals(fieldOne)
		isZ2One = z2.equals(fieldOne)
		if isZ1One and isZ2One:
			self.addZ1AndZ2EqualsOne(x1, y1, z1, x2, y2, x3, y3, z3)
			return
		if z1.equals(z2):
			self.addZ1EqualsZ2(x1, y1, z1, x2, y2, x3, y3, z3)
			return
		if isZ2One:
			self.addZ2EqualsOne(x1, y1, z1, x2, y2, x3, y3, z3)
			return
		# None of the above assumptions are true, so fall back to generic
		# point addition.
		self.addGeneric(x1, y1, z1, x2, y2, z2, x3, y3, z3)
	def add(self, x1, y1, x2, y2):
		"""
		Add returns the sum of (x1,y1) and (x2,y2). Part of the elliptic.Curve
		interface.
		"""
		# A point at infinity is the identity according to the group law for
		# elliptic curve cryptography.  Thus, ∞ + P = P and P + ∞ = P.
		if x1 == 0 and y1 == 0:
			return x2, y2
		if x2 == 0 == 0 and y2 == 0:
			return x1, y1

		# Convert the affine coordinates from big integers to field values
		# and do the point addition in Jacobian projective space.
		fx1, fy1 = curve.bigAffineToField(x1, y1)
		fx2, fy2 = curve.bigAffineToField(x2, y2)
		fv = FieldVal
		fx3, fy3, fz3, fOne = fv(), fv(), fv(), fv()
		fOne.setInt(1)
		self.addJacobian(fx1, fy1, fOne, fx2, fy2, fOne, fx3, fy3, fz3)

		# Convert the Jacobian coordinate field values back to affine big
		# integers.
		return self.fieldJacobianToBigAffine(fx3, fy3, fz3)

	def addZ1AndZ2EqualsOne(self, x1, y1, z1, x2, y2, x3, y3, z3):
		"""
		addZ1AndZ2EqualsOne adds two Jacobian points that are already known to have
		z values of 1 and stores the result in (x3, y3, z3).  That is to say
		(x1, y1, 1) + (x2, y2, 1) = (x3, y3, z3).  It performs faster addition than
		the generic add routine since less arithmetic is needed due to the ability to
		avoid the z value multiplications.
		"""
		# To compute the point addition efficiently, this implementation splits
		# the equation into intermediate elements which are used to minimize
		# the number of field multiplications using the method shown at:
		# http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-mmadd-2007-bl
		#
		# In particular it performs the calculations using the following:
		# H = X2-X1, HH = H^2, I = 4*HH, J = H*I, r = 2*(Y2-Y1), V = X1*I
		# X3 = r^2-J-2*V, Y3 = r*(V-X3)-2*Y1*J, Z3 = 2*H
		#
		# This results in a cost of 4 field multiplications, 2 field squarings,
		# 6 field additions, and 5 integer multiplications.

		# When the x coordinates are the same for two points on the curve, the
		# y coordinates either must be the same, in which case it is point
		# doubling, or they are opposite and the result is the point at
		# infinity per the group law for elliptic curve cryptography.
		x1.normalize()
		y1.normalize()
		x2.normalize()
		y2.normalize()
		if x1.equals(x2):
			if y1.equals(y2):
				# Since x1 == x2 and y1 == y2, point doubling must be
				# done, otherwise the addition would end up dividing
				# by zero.
				self.doubleJacobian(x1, y1, z1, x3, y3, z3)
				return


			# Since x1 == x2 and y1 == -y2, the sum is the point at
			# infinity per the group law.
			x3.setInt(0)
			y3.setInt(0)
			z3.setInt(0)
			return

		# Calculate X3, Y3, and Z3 according to the intermediate elements
		# breakdown above.
		fv = FieldVal
		h, i, j, r, v = fv(), fv(), fv(), fv(), fv()
		negJ, neg2V, negX3 = fv(), fv(), fv()
		h.set(x1).negate(1).add(x2)                # H = X2-X1 (mag: 3)
		i.squareVal(h).mulInt(4)                  # I = 4*H^2 (mag: 4)
		j.mul2(h, i)                             # J = H*I (mag: 1)
		r.set(y1).negate(1).add(y2).mulInt(2)      # r = 2*(Y2-Y1) (mag: 6)
		v.mul2(x1, i)                             # V = X1*I (mag: 1)
		negJ.set(j).negate(1)                     # negJ = -J (mag: 2)
		neg2V.set(v).mulInt(2).negate(2)          # neg2V = -(2*V) (mag: 3)
		x3.set(r).square().add(negJ).add(neg2V) # X3 = r^2-J-2*V (mag: 6)
		negX3.set(x3).negate(6)                    # negX3 = -X3 (mag: 7)
		j.mul(y1).mulInt(2).negate(2)              # J = -(2*Y1*J) (mag: 3)
		y3.set(v).add(negX3).mul(r).add(j)     # Y3 = r*(V-X3)-2*Y1*J (mag: 4)
		z3.set(h).mulInt(2)                       # Z3 = 2*H (mag: 6)

		# Normalize the resulting field values to a magnitude of 1 as needed.
		x3.normalize()
		y3.normalize()
		z3.normalize()

	def addZ1EqualsZ2(self, x1, y1, z1, x2, y2, x3, y3, z3):
		"""
		# addZ1EqualsZ2 adds two Jacobian points that are already known to have the
		# same z value and stores the result in (x3, y3, z3).  That is to say
		# (x1, y1, z1) + (x2, y2, z1) = (x3, y3, z3).  It performs faster addition than
		# the generic add routine since less arithmetic is needed due to the known
		# equivalence.
		"""
		# To compute the point addition efficiently, this implementation splits
		# the equation into intermediate elements which are used to minimize
		# the number of field multiplications using a slightly modified version
		# of the method shown at:
		# http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-mmadd-2007-bl
		
		# In particular it performs the calculations using the following:
		# A = X2-X1, B = A^2, C=Y2-Y1, D = C^2, E = X1*B, F = X2*B
		# X3 = D-E-F, Y3 = C*(E-X3)-Y1*(F-E), Z3 = Z1*A
		
		# This results in a cost of 5 field multiplications, 2 field squarings,
		# 9 field additions, and 0 integer multiplications.

		# When the x coordinates are the same for two points on the curve, the
		# y coordinates either must be the same, in which case it is point
		# doubling, or they are opposite and the result is the point at
		# infinity per the group law for elliptic curve cryptography.
		x1.normalize()
		y1.normalize()
		x2.normalize()
		y2.normalize()
		if x1.equals(x2):
			if y1.equals(y2):
				# Since x1 == x2 and y1 == y2, point doubling must be
				# done, otherwise the addition would end up dividing
				# by zero.
				self.doubleJacobian(x1, y1, z1, x3, y3, z3)
				return

			# Since x1 == x2 and y1 == -y2, the sum is the point at
			# infinity per the group law.
			x3.setInt(0)
			y3.setInt(0)
			z3.setInt(0)
			return

		# Calculate X3, Y3, and Z3 according to the intermediate elements
		# breakdown above.
		fv = FieldVal
		a, b, c, d, e, f = fv(), fv(), fv(), fv(), fv(), fv()
		negX1, negY1, negE, negX3 = fv(), fv(), fv(), fv()
		negX1.set(x1).negate(1)                # negX1 = -X1 (mag: 2)
		negY1.set(y1).negate(1)                # negY1 = -Y1 (mag: 2)
		a.set(negX1).add(x2)                  # A = X2-X1 (mag: 3)
		b.squareVal(a)                        # B = A^2 (mag: 1)
		c.set(negY1).add(y2)                  # C = Y2-Y1 (mag: 3)
		d.squareVal(c)                        # D = C^2 (mag: 1)
		e.mul2(x1, b)                         # E = X1*B (mag: 1)
		negE.set(e).negate(1)                 # negE = -E (mag: 2)
		f.mul2(x2, b)                         # F = X2*B (mag: 1)
		x3.add2(e, f).negate(3).add(d)      # X3 = D-E-F (mag: 5)
		negX3.set(x3).negate(5).normalize()    # negX3 = -X3 (mag: 1)
		y3.set(y1).mul(f.add(negE)).negate(3) # Y3 = -(Y1*(F-E)) (mag: 4)
		y3.add(e.add(negX3).mul(c))          # Y3 = C*(E-X3)+Y3 (mag: 5)
		z3.mul2(z1, a)                        # Z3 = Z1*A (mag: 1)

		# Normalize the resulting field values to a magnitude of 1 as needed.
		x3.normalize()
		y3.normalize()
	def addZ2EqualsOne(self, x1, y1, z1, x2, y2, x3, y3, z3): # *fieldVal) {
		"""
		addZ2EqualsOne adds two Jacobian points when the second point is already
		known to have a z value of 1 (and the z value for the first point is not 1)
		and stores the result in (x3, y3, z3).  That is to say (x1, y1, z1) +
		(x2, y2, 1) = (x3, y3, z3).  It performs faster addition than the generic
		add routine since less arithmetic is needed due to the ability to avoid
		multiplications by the second point's z value.
		"""
		# To compute the point addition efficiently, this implementation splits
		# the equation into intermediate elements which are used to minimize
		# the number of field multiplications using the method shown at:
		# http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
		
		# In particular it performs the calculations using the following:
		# Z1Z1 = Z1^2, U2 = X2*Z1Z1, S2 = Y2*Z1*Z1Z1, H = U2-X1, HH = H^2,
		# I = 4*HH, J = H*I, r = 2*(S2-Y1), V = X1*I
		# X3 = r^2-J-2*V, Y3 = r*(V-X3)-2*Y1*J, Z3 = (Z1+H)^2-Z1Z1-HH
		
		# This results in a cost of 7 field multiplications, 4 field squarings,
		# 9 field additions, and 4 integer multiplications.

		# When the x coordinates are the same for two points on the curve, the
		# y coordinates either must be the same, in which case it is point
		# doubling, or they are opposite and the result is the point at
		# infinity per the group law for elliptic curve cryptography.  Since
		# any number of Jacobian coordinates can represent the same affine
		# point, the x and y values need to be converted to like terms.  Due to
		# the assumption made for this function that the second point has a z
		# value of 1 (z2=1), the first point is already "converted".
		fv = FieldVal
		z1z1, u2, s2 = fv(), fv(), fv()
		x1.normalize()
		y1.normalize()
		z1z1.squareVal(z1)                        # Z1Z1 = Z1^2 (mag: 1)
		u2.set(x2).mul(z1z1).normalize()         # U2 = X2*Z1Z1 (mag: 1)
		s2.set(y2).mul(z1z1).mul(z1).normalize() # S2 = Y2*Z1*Z1Z1 (mag: 1)
		if x1.equals(u2):
			if y1.equals(s2):
				# Since x1 == x2 and y1 == y2, point doubling must be
				# done, otherwise the addition would end up dividing
				# by zero.
				self.doubleJacobian(x1, y1, z1, x3, y3, z3)
				return

			# Since x1 == x2 and y1 == -y2, the sum is the point at
			# infinity per the group law.
			x3.setInt(0)
			y3.setInt(0)
			z3.setInt(0)
			return

		# Calculate X3, Y3, and Z3 according to the intermediate elements
		# breakdown above.
		h, hh, i, j, r, rr, v = fv(), fv(), fv(), fv(), fv(), fv(), fv()
		negX1, negY1, negX3 = fv(), fv(), fv()
		negX1.set(x1).negate(1)               # negX1 = -X1 (mag: 2)
		h.add2(u2, negX1)                     # H = U2-X1 (mag: 3)
		hh.squareVal(h)                       # HH = H^2 (mag: 1)
		i.set(hh).mulInt(4)                   # I = 4 * HH (mag: 4)
		j.mul2(h, i)                          # J = H*I (mag: 1)
		negY1.set(y1).negate(1)               # negY1 = -Y1 (mag: 2)
		r.set(s2).add(negY1).mulInt(2)        # r = 2*(S2-Y1) (mag: 6)
		rr.squareVal(r)                       # rr = r^2 (mag: 1)
		v.mul2(x1, i)                         # V = X1*I (mag: 1)
		x3.set(v).mulInt(2).add(j).negate(3)  # X3 = -(J+2*V) (mag: 4)
		x3.add(rr)                            # X3 = r^2+X3 (mag: 5)
		negX3.set(x3).negate(5)               # negX3 = -X3 (mag: 6)
		y3.set(y1).mul(j).mulInt(2).negate(2) # Y3 = -(2*Y1*J) (mag: 3)
		y3.add(v.add(negX3).mul(r))           # Y3 = r*(V-X3)+Y3 (mag: 4)
		z3.add2(z1, h).square()               # Z3 = (Z1+H)^2 (mag: 1)
		z3.add(z1z1.add(hh).negate(2))        # Z3 = Z3-(Z1Z1+HH) (mag: 4)

		# Normalize the resulting field values to a magnitude of 1 as needed.
		x3.normalize()
		y3.normalize()
		z3.normalize()
	def doubleZ1EqualsOne(self, x1, y1, x3, y3, z3):
		"""
		doubleZ1EqualsOne performs point doubling on the passed Jacobian point
		when the point is already known to have a z value of 1 and stores
		the result in (x3, y3, z3).  That is to say (x3, y3, z3) = 2*(x1, y1, 1).  It
		performs faster point doubling than the generic routine since less arithmetic
		is needed due to the ability to avoid multiplication by the z value.
		"""
		# This function uses the assumptions that z1 is 1, thus the point
		# doubling formulas reduce to:

		# X3 = (3*X1^2)^2 - 8*X1*Y1^2
		# Y3 = (3*X1^2)*(4*X1*Y1^2 - X3) - 8*Y1^4
		# Z3 = 2*Y1

		# To compute the above efficiently, this implementation splits the
		# equation into intermediate elements which are used to minimize the
		# number of field multiplications in favor of field squarings which
		# are roughly 35% faster than field multiplications with the current
		# implementation at the time this was written.

		# This uses a slightly modified version of the method shown at:
		# http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-mdbl-2007-bl

		# In particular it performs the calculations using the following:
		# A = X1^2, B = Y1^2, C = B^2, D = 2*((X1+B)^2-A-C)
		# E = 3*A, F = E^2, X3 = F-2*D, Y3 = E*(D-X3)-8*C
		# Z3 = 2*Y1

		# This results in a cost of 1 field multiplication, 5 field squarings,
		# 6 field additions, and 5 integer multiplications.
		fv = FieldVal
		a, b, c, d, e, f = fv(), fv(), fv(), fv(), fv(), fv()
		z3.set(y1).mulInt(2)                     # Z3 = 2*Y1 (mag: 2)
		a.squareVal(x1)                          # A = X1^2 (mag: 1)
		b.squareVal(y1)                          # B = Y1^2 (mag: 1)
		c.squareVal(b)                           # C = B^2 (mag: 1)
		b.add(x1).square()                       # B = (X1+B)^2 (mag: 1)
		d.set(a).add(c).negate(2)                # D = -(A+C) (mag: 3)
		d.add(b).mulInt(2)                       # D = 2*(B+D)(mag: 8)
		e.set(a).mulInt(3)                       # E = 3*A (mag: 3)
		f.squareVal(e)                           # F = E^2 (mag: 1)
		x3.set(d).mulInt(2).negate(16)           # X3 = -(2*D) (mag: 17)
		x3.add(f)                                # X3 = F+X3 (mag: 18)
		f.set(x3).negate(18).add(d).normalize()  # F = D-X3 (mag: 1)
		y3.set(c).mulInt(8).negate(8)            # Y3 = -(8*C) (mag: 9)
		y3.add(f.mul(e))                         # Y3 = E*F+Y3 (mag: 10)

		# Normalize the field values back to a magnitude of 1.
		x3.normalize()
		y3.normalize()
		z3.normalize()

	def doubleJacobian(self, x1, y1, z1, x3, y3, z3):
		"""
		doubleJacobian doubles the passed Jacobian point (x1, y1, z1) and stores the
		result in (x3, y3, z3).
		"""
		# Doubling a point at infinity is still infinity.
		if y1.isZero() or z1.isZero():
			x3.setInt(0)
			y3.setInt(0)
			z3.setInt(0)
			return

		# Slightly faster point doubling can be achieved when the z value is 1
		# by avoiding the multiplication on the z value.  This section calls
		# a point doubling function which is accelerated by using that
		# assumption when possible.
		if z1.normalize().equals(fieldOne):
			self.doubleZ1EqualsOne(x1, y1, x3, y3, z3)
			return

		# Fall back to generic point doubling which works with arbitrary z
		# values.
		self.doubleGeneric(x1, y1, z1, x3, y3, z3)

	def addGeneric(self, x1, y1, z1, x2, y2, z2, x3, y3, z3):
		"""
		addGeneric adds two Jacobian points (x1, y1, z1) and (x2, y2, z2) without any
		assumptions about the z values of the two points and stores the result in
		(x3, y3, z3).  That is to say (x1, y1, z1) + (x2, y2, z2) = (x3, y3, z3).  It
		is the slowest of the add routines due to requiring the most arithmetic.
		"""
		# To compute the point addition efficiently, this implementation splits
		# the equation into intermediate elements which are used to minimize
		# the number of field multiplications using the method shown at:
		# http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
		
		# In particular it performs the calculations using the following:
		# Z1Z1 = Z1^2, Z2Z2 = Z2^2, U1 = X1*Z2Z2, U2 = X2*Z1Z1, S1 = Y1*Z2*Z2Z2
		# S2 = Y2*Z1*Z1Z1, H = U2-U1, I = (2*H)^2, J = H*I, r = 2*(S2-S1)
		# V = U1*I
		# X3 = r^2-J-2*V, Y3 = r*(V-X3)-2*S1*J, Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
		
		# This results in a cost of 11 field multiplications, 5 field squarings,
		# 9 field additions, and 4 integer multiplications.

		# When the x coordinates are the same for two points on the curve, the
		# y coordinates either must be the same, in which case it is point
		# doubling, or they are opposite and the result is the point at
		# infinity.  Since any number of Jacobian coordinates can represent the
		# same affine point, the x and y values need to be converted to like
		# terms.
		fv = FieldVal
		z1z1, z2z2, u1, u2, s1, s2 = fv(), fv(), fv(), fv(), fv(), fv()
		z1z1.squareVal(z1)                        # Z1Z1 = Z1^2 (mag: 1)
		z2z2.squareVal(z2)                        # Z2Z2 = Z2^2 (mag: 1)
		u1.set(x1).mul(z2z2).normalize()          # U1 = X1*Z2Z2 (mag: 1)
		u2.set(x2).mul(z1z1).normalize()          # U2 = X2*Z1Z1 (mag: 1)
		s1.set(y1).mul(z2z2).mul(z2).normalize()  # S1 = Y1*Z2*Z2Z2 (mag: 1)
		s2.set(y2).mul(z1z1).mul(z1).normalize()  # S2 = Y2*Z1*Z1Z1 (mag: 1)
		if u1.equals(u2):
			if s1.equals(s2):
				# Since x1 == x2 and y1 == y2, point doubling must be
				# done, otherwise the addition would end up dividing
				# by zero.
				self.doubleJacobian(x1, y1, z1, x3, y3, z3)
				return

			# Since x1 == x2 and y1 == -y2, the sum is the point at
			# infinity per the group law.
			x3.setInt(0)
			y3.setInt(0)
			z3.setInt(0)
			return

		# Calculate X3, Y3, and Z3 according to the intermediate elements
		# breakdown above.
		h, i, j, r, rr, v = fv(), fv(), fv(), fv(), fv(), fv()
		negU1, negS1, negX3 = fv(), fv(), fv()
		negU1.set(u1).negate(1)               # negU1 = -U1 (mag: 2)
		h.add2(u2, negU1)                     # H = U2-U1 (mag: 3)
		i.set(h).mulInt(2).square()           # I = (2*H)^2 (mag: 2)
		j.mul2(h, i)                          # J = H*I (mag: 1)
		negS1.set(s1).negate(1)               # negS1 = -S1 (mag: 2)
		r.set(s2).add(negS1).mulInt(2)        # r = 2*(S2-S1) (mag: 6)
		rr.squareVal(r)                       # rr = r^2 (mag: 1)
		v.mul2(u1, i)                         # V = U1*I (mag: 1)
		x3.set(v).mulInt(2).add(j).negate(3)  # X3 = -(J+2*V) (mag: 4)
		x3.add(rr)                            # X3 = r^2+X3 (mag: 5)
		negX3.set(x3).negate(5)               # negX3 = -X3 (mag: 6)
		y3.mul2(s1, j).mulInt(2).negate(2)    # Y3 = -(2*S1*J) (mag: 3)
		y3.add(v.add(negX3).mul(r))           # Y3 = r*(V-X3)+Y3 (mag: 4)
		z3.add2(z1, z2).square()              # Z3 = (Z1+Z2)^2 (mag: 1)
		z3.add(z1z1.add(z2z2).negate(2))      # Z3 = Z3-(Z1Z1+Z2Z2) (mag: 4)
		z3.mul(h)                             # Z3 = Z3*H (mag: 1)

		# Normalize the resulting field values to a magnitude of 1 as needed.
		x3.normalize()
		y3.normalize()

	def doubleGeneric(self, x1, y1, z1, x3, y3, z3):
		"""
		doubleGeneric performs point doubling on the passed Jacobian point without
		any assumptions about the z value and stores the result in (x3, y3, z3).
		That is to say (x3, y3, z3) = 2*(x1, y1, z1).  It is the slowest of the point
		doubling routines due to requiring the most arithmetic.
		"""
		# Point doubling formula for Jacobian coordinates for the secp256k1
		# curve:
		# X3 = (3*X1^2)^2 - 8*X1*Y1^2
		# Y3 = (3*X1^2)*(4*X1*Y1^2 - X3) - 8*Y1^4
		# Z3 = 2*Y1*Z1
		
		# To compute the above efficiently, this implementation splits the
		# equation into intermediate elements which are used to minimize the
		# number of field multiplications in favor of field squarings which
		# are roughly 35% faster than field multiplications with the current
		# implementation at the time this was written.
		
		# This uses a slightly modified version of the method shown at:
		# http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
		
		# In particular it performs the calculations using the following:
		# A = X1^2, B = Y1^2, C = B^2, D = 2*((X1+B)^2-A-C)
		# E = 3*A, F = E^2, X3 = F-2*D, Y3 = E*(D-X3)-8*C
		# Z3 = 2*Y1*Z1
		
		# This results in a cost of 1 field multiplication, 5 field squarings,
		# 6 field additions, and 5 integer multiplications.
		fv = FieldVal
		a, b, c, d, e, f = fv(), fv(), fv(), fv(), fv(), fv()
		z3.mul2(y1, z1).mulInt(2)               # Z3 = 2*Y1*Z1 (mag: 2)
		a.squareVal(x1)                         # A = X1^2 (mag: 1)
		b.squareVal(y1)                         # B = Y1^2 (mag: 1)
		c.squareVal(b)                          # C = B^2 (mag: 1)
		b.add(x1).square()                      # B = (X1+B)^2 (mag: 1)
		d.set(a).add(c).negate(2)               # D = -(A+C) (mag: 3)
		d.add(b).mulInt(2)                      # D = 2*(B+D)(mag: 8)
		e.set(a).mulInt(3)                      # E = 3*A (mag: 3)
		f.squareVal(e)                          # F = E^2 (mag: 1)
		x3.set(d).mulInt(2).negate(16)          # X3 = -(2*D) (mag: 17)
		x3.add(f)                               # X3 = F+X3 (mag: 18)
		f.set(x3).negate(18).add(d).normalize() # F = D-X3 (mag: 1)
		y3.set(c).mulInt(8).negate(8)           # Y3 = -(8*C) (mag: 9)
		y3.add(f.mul(e))                        # Y3 = E*F+Y3 (mag: 10)

		# Normalize the field values back to a magnitude of 1.
		x3.normalize()
		y3.normalize()
		z3.normalize()
	def fieldJacobianToBigAffine(self, x, y, z):
		"""
		fieldJacobianToBigAffine takes a Jacobian point (x, y, z) as field values and
		converts it to an affine point as big integers.
		"""
		# Inversions are expensive and both point addition and point doubling
		# are faster when working with points that have a z value of one.  So,
		# if the point needs to be converted to affine, go ahead and normalize
		# the point itself at the same time as the calculation is the same.
		zInv, tempZ = FieldVal(), FieldVal()
		zInv.set(z).inverse()   # zInv = Z^-1
		tempZ.squareVal(zInv)   # tempZ = Z^-2
		x.mul(tempZ)            # X = X/Z^2 (mag: 1)
		y.mul(tempZ.mul(zInv))  # Y = Y/Z^3 (mag: 1)
		z.setInt(1)             # Z = 1 (mag: 1)

		# Normalize the x and y values.
		x.normalize()
		y.normalize()

		# Convert the field values for the now affine point to big.Ints.
		return ByteArray(x.bytes()).int(), ByteArray(y.bytes()).int()

def fromHex(hx):
	return int(hx, 16)

class Curve(KoblitzCurve):
	def __init__(self):
		bitSize = 256
		p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
		super().__init__(
			P = p,
			N = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
			B = fromHex("0000000000000000000000000000000000000000000000000000000000000007"),
			Gx = fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
			Gy = fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
			BitSize = bitSize,
			H = 1,
			q =  (p + 1) // 4, # new(big.Int).Div(new(big.Int).Add(secp256k1.P, big.NewInt(1)), big.NewInt(4)),
			# Provided for convenience since this gets computed repeatedly.
			# lambda is a reserved keyword in Python, so misspelling on purpose.
			byteSize = bitSize / 8,
			# Next 6 constants are from Hal Finney's bitcointalk.org post:
			# https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
			# May he rest in peace.
			#
			# They have also been independently derived from the code in the
			# EndomorphismVectors function in gensecp256k1.go.
			lamda = fromHex("5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72"),
			beta = FieldVal.fromHex("7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE"),
			a1 = fromHex("3086D221A7D46BCDE86C90E49284EB15"),
			b1 = fromHex("-E4437ED6010E88286F547FA90ABFE4C3"),
			a2 = fromHex("114CA50F7A8E2F3F657C1108D9D44CFD8"),
			b2 = fromHex("3086D221A7D46BCDE86C90E49284EB15"),
		)
	def bigAffineToField(self, x, y):
		"""
		bigAffineToField takes an affine point (x, y) as big integers and converts
		it to an affine point as field values.
		"""
		x3, y3 = FieldVal(), FieldVal()
		x3.setBytes(ByteArray(x).bytes())
		y3.setBytes(ByteArray(y).bytes())
		return x3, y3
	def isAffineOnCurve(self, x, y):
		"""
		isAffineOnCurve returns boolean if the point (x,y) is on the
		secp256k1 curve.
		"""
		# y² = x³ + b
		y2 = y**2 % self.P

		x3 = (x**3 + self.B) % self.P

		return y2 == x3

curve = Curve()

def isJacobianOnS256Curve(x, y, z):
	"""
	isJacobianOnS256Curve returns boolean if the point (x,y,z) is on the
	secp256k1 curve.
	Elliptic curve equation for secp256k1 is: y^2 = x^3 + 7
	In Jacobian coordinates, Y = y/z^3 and X = x/z^2
	Thus:
	(y/z^3)^2 = (x/z^2)^3 + 7
	y^2/z^6 = x^3/z^6 + 7
	y^2 = x^3 + 7*z^6
	"""
	fv = FieldVal
	y2, z2, x3, result = fv(), fv(), fv(), fv()
	y2.squareVal(y).normalize()
	z2.squareVal(z)
	x3.squareVal(x).mul(x)
	result.squareVal(z2).mul(z2).mulInt(7).add(x3).normalize()
	return y2.equals(result)

class TestCurve(unittest.TestCase):
	def test_add_jacobian(self):
		""" TestAddJacobian tests addition of points projected in Jacobian coordinates."""
		# x1, y1, z1 string // Coordinates (in hex) of first point to add
		# x2, y2, z2 string // Coordinates (in hex) of second point to add
		# x3, y3, z3 string // Coordinates (in hex) of expected point
		tests = [
			# Addition with a point at infinity (left hand side).
			# ∞ + P = P
			(
				"0",
				"0",
				"0",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"1",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"1",
			),
			# Addition with a point at infinity (right hand side).
			# P + ∞ = P
			(
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"1",
				"0",
				"0",
				"0",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"1",
			),
			# Addition with z1=z2=1 different x values.
			(
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"1",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"1",
				"0cfbc7da1e569b334460788faae0286e68b3af7379d5504efc25e4dba16e46a6",
				"e205f79361bbe0346b037b4010985dbf4f9e1e955e7d0d14aca876bfa79aad87",
				"44a5646b446e3877a648d6d381370d9ef55a83b666ebce9df1b1d7d65b817b2f",
			),
			# Addition with z1=z2=1 same x opposite y.
			# P(x, y, z) + P(x, -y, z) = infinity
			(
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"1",
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
				"1",
				"0",
				"0",
				"0",
			),
			# Addition with z1=z2=1 same point.
			# P(x, y, z) + P(x, y, z) = 2P
			(
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"1",
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"1",
				"ec9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee64f87c50c27",
				"b082b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd0755c8f2a",
				"16e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c1e594464",
			),

			# Addition with z1=z2 (!=1) different x values.
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"5d2fe112c21891d440f65a98473cb626111f8a234d2cd82f22172e369f002147",
				"98e3386a0a622a35c4561ffb32308d8e1c6758e10ebb1b4ebd3d04b4eb0ecbe8",
				"2",
				"cfbc7da1e569b334460788faae0286e68b3af7379d5504efc25e4dba16e46a60",
				"817de4d86ef80d1ac0ded00426176fd3e787a5579f43452b2a1db021e6ac3778",
				"129591ad11b8e1de99235b4e04dc367bd56a0ed99baf3a77c6c75f5a6e05f08d",
			),
			# Addition with z1=z2 (!=1) same x opposite y.
			# P(x, y, z) + P(x, -y, z) = infinity
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"a470ab21467813b6e0496d2c2b70c11446bab4fcbc9a52b7f225f30e869aea9f",
				"2",
				"0",
				"0",
				"0",
			),
			# Addition with z1=z2 (!=1) same point.
			# P(x, y, z) + P(x, y, z) = 2P
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
				"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
				"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
			),

			# Addition with z1!=z2 and z2=1 different x values.
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"1",
				"3ef1f68795a6ccd1181e23eab80a1b9a2cebdcde755413bf097936eb5b91b4f3",
				"0bef26c377c068d606f6802130bb7e9f3c3d2abcfa1a295950ed81133561cb04",
				"252b235a2371c3bd3246b69c09b86cf7aad41db3375e74ef8d8ebeb4dc0be11a",
			),
			# Addition with z1!=z2 and z2=1 same x opposite y.
			# P(x, y, z) + P(x, -y, z) = infinity
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
				"1",
				"0",
				"0",
				"0",
			),
			# Addition with z1!=z2 and z2=1 same point.
			# P(x, y, z) + P(x, y, z) = 2P
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"1",
				"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
				"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
				"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
			),

			# Addition with z1!=z2 and z2!=1 different x values.
			# P(x, y, z) + P(x, y, z) = 2P
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"91abba6a34b7481d922a4bd6a04899d5a686f6cf6da4e66a0cb427fb25c04bd4",
				"03fede65e30b4e7576a2abefc963ddbf9fdccbf791b77c29beadefe49951f7d1",
				"3",
				"3f07081927fd3f6dadd4476614c89a09eba7f57c1c6c3b01fa2d64eac1eef31e",
				"949166e04ebc7fd95a9d77e5dfd88d1492ecffd189792e3944eb2b765e09e031",
				"eb8cba81bcffa4f44d75427506737e1f045f21e6d6f65543ee0e1d163540c931",
			), 
			# Addition with z1!=z2 and z2!=1 same x opposite y.
			# P(x, y, z) + P(x, -y, z) = infinity
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"dcc3768780c74a0325e2851edad0dc8a566fa61a9e7fc4a34d13dcb509f99bc7",
				"cafc41904dd5428934f7d075129c8ba46eb622d4fc88d72cd1401452664add18",
				"3",
				"0",
				"0",
				"0",
			),
			# Addition with z1!=z2 and z2!=1 same point.
			# P(x, y, z) + P(x, y, z) = 2P
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"dcc3768780c74a0325e2851edad0dc8a566fa61a9e7fc4a34d13dcb509f99bc7",
				"3503be6fb22abd76cb082f8aed63745b9149dd2b037728d32ebfebac99b51f17",
				"3",
				"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
				"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
				"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
			),
		]

		for i, (x1, y1, z1, x2, y2, z2, x3, y3, z3) in enumerate(tests):
			# Convert hex to field values.
			x1 = FieldVal.fromHex(x1)
			y1 = FieldVal.fromHex(y1)
			z1 = FieldVal.fromHex(z1)
			x2 = FieldVal.fromHex(x2)
			y2 = FieldVal.fromHex(y2)
			z2 = FieldVal.fromHex(z2)
			x3 = FieldVal.fromHex(x3)
			y3 = FieldVal.fromHex(y3)
			z3 = FieldVal.fromHex(z3)

			# Ensure the test data is using points that are actually on
			# the curve (or the point at infinity).
			self.assertFalse(not z1.isZero() and not isJacobianOnS256Curve(x1, y1, z1), msg="xyz1")
			self.assertFalse(not z2.isZero() and not isJacobianOnS256Curve(x2, y2, z2), msg="xyz1")
			self.assertFalse(not z3.isZero() and not isJacobianOnS256Curve(x3, y3, z3), msg="xyz1")

			# Add the two points.
			fv = FieldVal
			rx, ry, rz = fv(), fv(), fv()
			curve.addJacobian(x1, y1, z1, x2, y2, z2, rx, ry, rz)
			self.assertTrue(rx.equals(x3), msg="x-%i" % i)
			self.assertTrue(ry.equals(y3), msg="y-%i" % i)
			self.assertTrue(rz.equals(z3), msg="z-%i" % i)
	def test_double_jacobian(self):
		""" TestDoubleJacobian tests doubling of points projected in Jacobian coordinates."""
		# x1, y1, z1 string // Coordinates (in hex) of point to double
		# 	x3, y3, z3 string // Coordinates (in hex) of expected point
		tests = [
			# Doubling a point at infinity is still infinity.
			(
				"0",
				"0",
				"0",
				"0",
				"0",
				"0",
			),
			# Doubling with z1=1.
			(
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"1",
				"ec9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee64f87c50c27",
				"b082b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd0755c8f2a",
				"16e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c1e594464",
			),
			# Doubling with z1!=1.
			(
				"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
				"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
				"2",
				"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
				"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
				"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
			),
			# From btcd issue #709.
			(
				"201e3f75715136d2f93c4f4598f91826f94ca01f4233a5bd35de9708859ca50d",
				"bdf18566445e7562c6ada68aef02d498d7301503de5b18c6aef6e2b1722412e1",
				"0000000000000000000000000000000000000000000000000000000000000001",
				"4a5e0559863ebb4e9ed85f5c4fa76003d05d9a7626616e614a1f738621e3c220",
				"00000000000000000000000000000000000000000000000000000001b1388778",
				"7be30acc88bceac58d5b4d15de05a931ae602a07bcb6318d5dedc563e4482993",
			),
		]

		for i, (x1, y1, z1, x3, y3, z3) in enumerate(tests):
			# Convert hex to field values.
			x1 = FieldVal.fromHex(x1)
			y1 = FieldVal.fromHex(y1)
			z1 = FieldVal.fromHex(z1)
			x3 = FieldVal.fromHex(x3)
			y3 = FieldVal.fromHex(y3)
			z3 = FieldVal.fromHex(z3)

			# Ensure the test data is using points that are actually on
			# the curve (or the point at infinity).
			self.assertFalse(not z1.isZero() and not isJacobianOnS256Curve(x1, y1, z1), msg="1-%i" % i)
			self.assertFalse(not z3.isZero() and not isJacobianOnS256Curve(x3, y3, z3), msg="3-%i" % i)
			# Double the point.
			fv = FieldVal
			rx, ry, rz = fv(), fv(), fv()
			curve.doubleJacobian(x1, y1, z1, rx, ry, rz)
			self.assertTrue(rx.equals(x3), msg="x-%i" % i)
			self.assertTrue(ry.equals(y3), msg="y-%i" % i)
			self.assertTrue(rz.equals(z3), msg="z-%i" % i)
	def test_base_mult(self):
		tests = [
			(
				"AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
				"34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
				"B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
			),
			(
				"7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
				"D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
				"131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
			),
			(
				"6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
				"E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
				"C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
			),
			(
				"376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
				"14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
				"297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
			),
			(
				"1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
				"F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
				"F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
			),
		]

		for i, (k, x, y) in enumerate(tests):
			px, py = curve.scalarBaseMult(fromHex(k))
			self.assertEqual(px, fromHex(x))
			self.assertEqual(py, fromHex(y))
	def test_add_affine(self):
		""" TestAddAffine tests addition of points in affine coordinates."""
		tests = [
			# Addition with a point at infinity (left hand side).
			# ∞ + P = P
			(
				"0",
				"0",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			),
			# Addition with a point at infinity (right hand side).
			# P + ∞ = P
			(
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"0",
				"0",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			),

			# Addition with different x values.
			(
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
				"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
				"fd5b88c21d3143518d522cd2796f3d726793c88b3e05636bc829448e053fed69",
				"21cf4f6a5be5ff6380234c50424a970b1f7e718f5eb58f68198c108d642a137f",
			),
			# Addition with same x opposite y.
			# P(x, y) + P(x, -y) = infinity
			(
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
				"0",
				"0",
			),
			# Addition with same point.
			# P(x, y) + P(x, y) = 2P
			(
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
				"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
				"59477d88ae64a104dbb8d31ec4ce2d91b2fe50fa628fb6a064e22582196b365b",
				"938dc8c0f13d1e75c987cb1a220501bd614b0d3dd9eb5c639847e1240216e3b6",
			),
		]

		for i, (x1, y1, x2, y2, x3, y3) in enumerate(tests):
			# Convert hex to field values.
			x1, y1 = fromHex(x1), fromHex(y1)
			x2, y2 = fromHex(x2), fromHex(y2)
			x3, y3 = fromHex(x3), fromHex(y3)

			# Ensure the test data is using points that are actually on
			# the curve (or the point at infinity).
			self.assertFalse(not (x1 == 0 and y1 == 0) and  not curve.isAffineOnCurve(x1, y1), msg="xy1")
			self.assertFalse(not (x2 == 0 and y2 == 0) and  not curve.isAffineOnCurve(x2, y2), msg="xy2")
			self.assertFalse(not (x3 == 0 and y3 == 0) and  not curve.isAffineOnCurve(x3, y3), msg="xy3")

			# Add the two points.
			rx, ry = curve.add(x1, y1, x2, y2)

			# Ensure result matches expected.
			self.assertEqual(rx, x3)
			self.assertEqual(ry, y3)