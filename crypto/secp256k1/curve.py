from tinydecred.crypto.secp256k1.field import FieldVal, BytePoints
from tinydecred.crypto.bytearray import ByteArray
import unittest

fieldOne = FieldVal.fromInt(1)

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
			q =  (p + 1) / 4, # new(big.Int).Div(new(big.Int).Add(secp256k1.P, big.NewInt(1)), big.NewInt(4)),
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