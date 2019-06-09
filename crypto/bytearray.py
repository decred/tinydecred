from tinydecred.pydecred import json
from tinydecred.crypto.rando import generateSeed
import nacl.secret
import unittest

def decodeBA(b, copy=False):
	"""
	Decode into a bytearray, as a copy if requested and possible.
	"""
	if isinstance(b, ByteArray):
		return bytearray(b.b) if copy else b.b
	if isinstance(b, bytearray):
		return bytearray(b) if copy else b
	if isinstance(b, bytes):
		return bytearray(b)
	if isinstance(b, int):
		return bytearray(b.to_bytes((b.bit_length() + 7) // 8, byteorder="big"))
	if isinstance(b, str):
		return bytearray.fromhex(b)
	raise TypeError("decodeBA: unknown type %s" % type(b))

class ByteArray:
	"""
	ByteArray is a bytearray manager that also implements the helpers.JSONMarshaller interface.
	It implements a subset of bytearray's bitwise operators and provides some convenience
	decodings on the fly, so operations work with various types of input. 
	Since bytearrays are mutable, ByteArray can provide additional controls of the memory
	occupied, such as zeroing the internal value. 
	An important difference between the constructors of ByteArray and bytearray is that 
	an int argument for b to ByteArray constructor will result in the shortest possible 
	bytearray representation of the integer, where for bytearray an int argument results 
	in a zero-valued bytearray of said length. To get a zero-valued ByteArray of length n,
	provides a bytearray(n) to the ByteArray constructor.
	"""
	def __init__(self, b=b'', copy=True, length=None):
		"""
		Set copy to False if you want to share the memory with another bytearray/ByteArray. 
		If the type of b is not bytearray or ByteArray, copy has no effect.
		"""
		if length:
			self.b = decodeBA(ByteArray(bytearray(length)) | b, copy=False)
		else:
			self.b = decodeBA(b, copy=copy)
	def __tojson__(self):
		return {
			"b": self.b.hex()
		}
	@staticmethod
	def __fromjson__(obj):
		return ByteArray(obj["b"])
	def decode(self, a):
		a = decodeBA(a)
		aLen, bLen = len(a), len(self.b)
		assert aLen <= bLen, "decode: invalid length %i > %i" % (aLen, bLen)
		return a, aLen, self.b, bLen
	def __lt__(self, a):
		return bytearray.__lt__(self.b, decodeBA(a))
	def __le__(self, a):
		return bytearray.__le__(self.b, decodeBA(a))
	def __eq__(self, a):
		return bytearray.__eq__(self.b, decodeBA(a))
	def __ne__(self, a):
		return bytearray.__ne__(self.b, decodeBA(a))
	def __ge__(self, a):
		return bytearray.__ge__(self.b, decodeBA(a))
	def __gt__(self, a):
		return bytearray.__gt__(self.b, decodeBA(a))
	def __repr__(self):
		return "ByteArray("+str(self.b)+")"
	def __len__(self):
		return len(self.b)
	def __and__(self, a):
		a, aLen, b, bLen = self.decode(a)
		b = ByteArray(b)
		for i in range(bLen):
			b[bLen-i-1] &= a[aLen-i-1] if i < aLen else 0
		return b
	def __iand__(self, a):
		a, aLen, b, bLen = self.decode(a)		
		for i in range(bLen):
			b[bLen-i-1] &= a[aLen-i-1] if i < aLen else 0
		return self
	def __or__(self, a):
		a, aLen, b, bLen = self.decode(a)
		b = ByteArray(b)
		for i in range(bLen):
			b[bLen-i-1] |= a[aLen-i-1] if i < aLen else 0
		return b
	def __ior__(self, a):
		a, aLen, b, bLen = self.decode(a)
		for i in range(bLen):
			b[bLen-i-1] |= a[aLen-i-1] if i < aLen else 0
		return self
	def __iadd__(self, a):
		"""append the bytes and return a new ByteArray"""
		a = decodeBA(a)
		return ByteArray(self.b + a)
	def __getitem__(self, k):
		if isinstance(k, slice):
			return ByteArray(self.b[k.start:k.stop:k.step], copy=False)
		return self.b[k]
	def __setitem__(self, i, v):
		v = decodeBA(v, copy=False)
		assert i + len(v) <= len(self.b), "source bytes too long"
		for j in range(len(v)):
			self.b[i+j] = v[j]
	def hex(self):
		return self.b.hex()
	def zero(self):
		for i in range(len(self.b)):
			self.b[i] = 0
	def iszero(self):
		return all([v==0 for v in self.b])
	def int(self):
		return int.from_bytes(self.b, "big")
	def bytes(self):
		return bytes(self.b)
	def encrypt(self, thing):
		nonce = ByteArray(generateSeed(nacl.secret.SecretBox.NONCE_SIZE))

		# This is your safe, you can use it to encrypt or decrypt messages
		box = nacl.secret.SecretBox(self.bytes())

		# Encrypt our message, it will be exactly 40 bytes longer than the
		#   original message as it stores authentication information and the
		#   nonce alongside it.
		encrypted = ByteArray(box.encrypt(thing, nonce.bytes()))

		assert len(encrypted) == len(thing) + box.NONCE_SIZE + box.MACBYTES

		return encrypted
	def decrypt(self, thing):
		return nacl.secret.SecretBox(self.bytes()).decrypt(thing)

# register the ByteArray class with the json encoder/decoder.
json.register(ByteArray)

class TestByteArray(unittest.TestCase):
	def test_operators(self):
		makeA = lambda: ByteArray(bytearray([0, 0, 255]))
		makeB = lambda: ByteArray(bytearray([0, 255, 0]))
		makeC = lambda: ByteArray(bytearray([255, 0, 0]))
		zero = ByteArray(bytearray([0, 0, 0]))

		a = makeA()
		b = makeB()
		a |= b
		self.assertEqual(a, bytearray([0, 255, 255]))

		c = makeC()
		a &= c
		self.assertEqual(a, zero)

		a = makeA()
		a.zero()
		self.assertEqual(a, zero)

		c = makeA()
		c |= 0
		self.assertEqual(a, zero)

		zero2 = ByteArray(zero)
		self.assertFalse(zero.b is zero2.b)
		self.assertEqual(zero, zero2)

		zero2 = ByteArray(zero, copy=False)
		self.assertTrue(zero.b is zero2.b)

		a = makeA()
		a |= makeC()
		a |= 65280
		self.assertEqual(a, bytearray([255, 255, 255]))
		self.assertFalse(a == makeB())

		self.assertTrue(makeA() < makeB())
		self.assertTrue(makeC() > makeB())
		self.assertTrue(makeA() != makeB())
		self.assertTrue(makeA() <= makeA())
		self.assertTrue(makeB() >= makeA())

		a = makeA()
		a2 = ByteArray(zero)
		a2 |= a[2:]
		self.assertTrue(not a is a2)
		self.assertEqual(a, a2)
		self.assertEqual(a[2], 255)

		z = ByteArray(zero)
		z[2] = 255
		self.assertEqual(makeA(), z)
