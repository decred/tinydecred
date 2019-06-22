from tinydecred.pydecred import dcrjson as json
from tinydecred.crypto.secp256k1.curve import curve as Curve, PublicKey, PrivateKey
from tinydecred.crypto.rando import generateSeed
from tinydecred.crypto.bytearray import ByteArray, decodeBA
from blake256.blake256 import blake_hash
from base58 import b58encode, b58decode
import hashlib
import pyaes
import base64
import hmac
import unittest

KEY_SIZE = 32
HASH_SIZE = 32
BLAKE256_SIZE = 32
SERIALIZED_KEY_LENGTH = 4 + 1 + 4 + 4 + 32 + 33 # 78 bytes
HARDENED_KEY_START = 2**31
MAX_COIN_TYPE = HARDENED_KEY_START - 1
MAX_ACCOUNT_NUM = HARDENED_KEY_START - 2
RADIX = 58
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ExternalBranch is the child number to use when performing BIP0044
# style hierarchical deterministic key derivation for the external
# branch.
EXTERNAL_BRANCH = 0

# InternalBranch is the child number to use when performing BIP0044
# style hierarchical deterministic key derivation for the internal
# branch.
INTERNAL_BRANCH = 1

# DEFAULT_SCRYPT_OPTIONS is the default options used with scrypt.
DEFAULT_SCRYPT_OPTIONS = {
	"N": 262144, # 2^18
	"R": 8,
	"P": 1,
}

# STEcdsaSecp256k1 specifies that the signature is an ECDSA signature
# over the secp256k1 elliptic curve.
STEcdsaSecp256k1 = 0

# STEd25519 specifies that the signature is an ECDSA signature over the
# edwards25519 twisted Edwards curve.
STEd25519 = 1

# STSchnorrSecp256k1 specifies that the signature is a Schnorr
# signature over the secp256k1 elliptic curve.
STSchnorrSecp256k1 = 2

class ParameterRangeError(Exception):
	pass
class ZeroBytesError(Exception):
	pass
class PasswordError(Exception):
	pass

class Address:
    def __init__(self, netID=None, pkHash=None, net=None):
        self.netID = netID
        self.pkHash = pkHash
        self.net = net
    def string(self):
        b = ByteArray(self.netID)
        b += self.pkHash
        b += checksum(b.b)
        x = b.int()

        answer = ""

        while x > 0:
            m = x%RADIX
            x = x//RADIX
            answer += ALPHABET[m]

        while len(answer) < len(b)*136//100:
            answer += ALPHABET[0]

        # reverse
        return answer[::-1]

def defaultScryptParams():
	d = DEFAULT_SCRYPT_OPTIONS
	return d["N"], d["R"], d["P"]

def hash160(b):
	h = hashlib.new("ripemd160")
	h.update(blake_hash(b))
	return ByteArray(h.digest())

def checksum(input):
	return blake_hash(blake_hash(input))[:4]

def sha256ChecksumByte(input):
	v = hashlib.sha256(input).digest()
	return hashlib.sha256(v).digest()[0]

def mac(key, msg):
	return ByteArray(hmac.digest(key.bytes(), msg=msg.bytes(), digest=hashlib.sha256))

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modInv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def hashH(b):
	return ByteArray(blake_hash(b), length=BLAKE256_SIZE)

def privKeyFromBytes(pk):
	"""
	PrivKeyFromBytes returns a private and public key for `curve' based on the
	private key passed as an argument as a byte slice.
	"""
	x, y = Curve.scalarBaseMult(pk.int())
	return PrivateKey(Curve, pk, x, y)

def b58CheckDecode(s):
	decoded = b58decode(s)
	if len(decoded) < 6:
		raise Exception("decoded lacking version/checksum")
	version = decoded[:2]
	cksum =decoded[len(decoded)-4:]
	if checksum(decoded[:len(decoded)-4]) != cksum:
		raise Exception("checksum error")
	payload = decoded[2 : len(decoded)-4]
	return payload, version

def newAddressPubKeyHash(pkHash, net, algo): # pkHash []byte, net *chaincfg.Params, algo dcrec.SignatureType) (*AddressPubKeyHash, error) {
    """ NewAddressPubKeyHash returns a new AddressPubKeyHash.  pkHash must be 20 bytes. """
    if algo == STEcdsaSecp256k1:
        netID = net.PubKeyHashAddrID
    elif algo == STEd25519:
        netID = net.PKHEdwardsAddrID
    elif algo == STSchnorrSecp256k1:
        netID = net.PKHSchnorrAddrID
    else:
        raise Exception("unknown ECDSA algorithm")
    return Address(netID, pkHash, net)

class ExtendedKey:
	def __init__(self, privVer, pubVer, key, pubKey, chainCode, parentFP, depth, childNum, isPrivate):
		"""
		# return newExtendedKey(k.privVer, k.pubVer,       childKey, childChainCode, parentFP,        k.depth+1,    i,               isPrivate), nil
		# 					  privVer,   pubVer [4]byte, key,      chainCode,      parentFP []byte, depth uint16, childNum uint32, isPrivate bool
		"""
		assert len(privVer) == 4 and len(pubVer) == 4, "Network version bytes of incorrect length"
		self.privVer = ByteArray(privVer)
		self.pubVer = ByteArray(pubVer)
		self.key = ByteArray(key)
		self.pubKey = ByteArray(pubKey)
		if self.pubKey.iszero():
			if isPrivate:
				self.pubKey = Curve.publicKey(self.key.int()).serializeCompressed()
			else:
				self.pubKey = self.key
		self.chainCode = ByteArray(chainCode)
		self.parentFP = ByteArray(parentFP)
		self.depth = depth
		self.childNum = childNum
		self.isPrivate = isPrivate
	def __tojson__(self):
		return {
			"privVer": self.privVer,
			"pubVer": self.pubVer,
			"key": self.key,
			"pubKey": self.pubKey,
			"chainCode": self.chainCode,
			"parentFP": self.parentFP,
			"depth": self.depth,
			"childNum": self.childNum,
			"isPrivate": self.isPrivate,
		}
	@staticmethod
	def __fromjson__(obj):
		return ExtendedKey(
			privVer = obj["privVer"], 
			pubVer = obj["pubVer"], 
			key = obj["key"],
			pubKey = obj["pubKey"],
			chainCode = obj["chainCode"], 
			parentFP = obj["parentFP"], 
			depth = obj["depth"], 
			childNum = obj["childNum"], 
			isPrivate = obj["isPrivate"],
		)
	def deriveCoinTypeKey(self, coinType):
		if coinType > MAX_COIN_TYPE:
			raise ParameterRangeError("coinType too high. %i > %i" % (coinType, MAX_COIN_TYPE))

		purpose = self.child(44 + HARDENED_KEY_START)
		
		# Derive the purpose key as a child of the master node.
		return purpose.child(coinType + HARDENED_KEY_START)
	def child(self, i):
		"""
		Child returns a derived child extended key at the given index.  When this
		extended key is a private extended key (as determined by the IsPrivate
		function), a private extended key will be derived.  Otherwise, the derived
		extended key will be also be a public extended key.
				
		When the index is greater to or equal than the HardenedKeyStart constant, the
		derived extended key will be a hardened extended key.  It is only possible to
		derive a hardended extended key from a private extended key.  Consequently,
		this function will return ErrDeriveHardFromPublic if a hardened child
		extended key is requested from a public extended key.
				
		A hardened extended key is useful since, as previously mentioned, it requires
		a parent private extended key to derive.  In other words, normal child
		extended public keys can be derived from a parent public extended key (no
		knowledge of the parent private key) whereas hardened extended keys may not
		be.
				
		NOTE: There is an extremely small chance (< 1 in 2^127) the specific child
		index does not derive to a usable child.  The ErrInvalidChild error will be
		returned if this should occur, and the caller is expected to ignore the
		invalid child and simply increment to the next index.

		There are four scenarios that could happen here:
		1) Private extended key -> Hardened child private extended key
		2) Private extended key -> Non-hardened child private extended key
		3) Public extended key -> Non-hardened child public extended key
		4) Public extended key -> Hardened child public extended key (INVALID!)
		"""

		# Case #4 is invalid, so error out early.
		# A hardened child extended key may not be created from a public
		# extended key.
		isChildHardened = i >= HARDENED_KEY_START
		if not self.isPrivate and isChildHardened:
			raise ParameterRangeError("cannot generate hardened child from public extended key")

		# The data used to derive the child key depends on whether or not the
		# child is hardened per [BIP32].
		#
		# For hardened children:
		#   0x00 || ser256(parentKey) || ser32(i)
		#
		# For normal children:
		#   serP(parentPubKey) || ser32(i)
		keyLen = 33
		data = ByteArray(bytearray(keyLen+4))

		if isChildHardened:
			# Case #1.
			# When the child is a hardened child, the key is known to be a
			# private key due to the above early return.  Pad it with a
			# leading zero as required by [BIP32] for deriving the child.
			data[1] = self.key
		else:
			# Case #2 or #3.
			# This is either a public or private extended key, but in
			# either case, the data which is used to derive the child key
			# starts with the secp256k1 compressed public key bytes.
			data[0] = ByteArray(self.pubKey)
		data[keyLen] = ByteArray(i, length=len(data)-keyLen)
		
		data |= i # ByteArray will handle the type conversion

		# Take the HMAC-SHA512 of the current key's chain code and the derived
		# data:
		#   I = HMAC-SHA512(Key = chainCode, Data = data)
		ilr = ByteArray(hmac.digest(self.chainCode.b, msg=data.b, digest=hashlib.sha512))

		# Split "I" into two 32-byte sequences Il and Ir where:
		#   Il = intermediate key used to derive the child
		#   Ir = child chain code
		il = ilr[:len(ilr)//2]
		childChainCode = ilr[len(ilr)//2:]

		# Both derived public or private keys rely on treating the left 32-byte
		# sequence calculated above (Il) as a 256-bit integer that must be
		# within the valid range for a secp256k1 private key.  There is a small
		# chance (< 1 in 2^127) this condition will not hold, and in that case,
		# a child extended key can't be created for this index and the caller
		# should simply increment to the next index.
		if il.int() >= Curve.N or il.iszero():
			raise ParameterRangeError("ExtendedKey.child: generated Il outside valid range")

		# The algorithm used to derive the child key depends on whether or not
		# a private or public child is being derived.
		#
		# For private children:
		#   childKey = parse256(Il) + parentKey
		#
		# For public children:
		#   childKey = serP(point(parse256(Il)) + parentKey)
		isPrivate = False
		if self.isPrivate:
			# Case #1 or #2.
			# Add the parent private key to the intermediate private key to
			# derive the final child key.
			#
			# childKey = parse256(Il) + parenKey
			childKey = ByteArray((self.key.int() + il.int()) % Curve.N)
			isPrivate = True
		else:
			# Case #3.
			# Calculate the corresponding intermediate public key for
			# intermediate private key.

			x, y = Curve.scalarBaseMult(il.int()) # Curve.G as ECPointJacobian
			if x == 0 or y == 0:
				raise ParameterRangeError("ExtendedKey.child: generated pt outside valid range")
			# Convert the serialized compressed parent public key into X
			# and Y coordinates so it can be added to the intermediate
			# public key.
			pubKey = Curve.parsePubKey(self.key)
			# Add the intermediate public key to the parent public key to
			# derive the final child key.
			#
			# childKey = serP(point(parse256(Il)) + parentKey)
			# childX, childY := curve.Add(pt.x, pt.y, pubKey.X, pubKey.Y)
			childX, childY = Curve.add(x, y, pubKey.x, pubKey.y)
			# pk := secp256k1.PublicKey{Curve: secp256k1.S256(), X: childX, Y: childY}
			# childKey = pk.SerializeCompressed()
			childKey = PublicKey(Curve, childX, childY).serializeCompressed()

		# The fingerprint of the parent for the derived child is the first 4
		# bytes of the RIPEMD160(BLAKE256(parentPubKey)).

		# parentFP := dcrutil.Hash160(k.pubKeyBytes())[:4]
		# return newExtendedKey(k.privVer, k.pubVer,       childKey, childChainCode, parentFP,        k.depth+1,    i,               isPrivate), nil
		# 					  privVer,   pubVer [4]byte, key,      chainCode,      parentFP []byte, depth uint16, childNum uint32, isPrivate bool

		parentFP = hash160(self.pubKey.b)[:4]

		return ExtendedKey(
			privVer = self.privVer,
			pubVer = self.pubVer,
			key = childKey,
			pubKey = "",
			chainCode = childChainCode,
			parentFP = parentFP,
			depth = self.depth + 1,
			childNum = i,
			isPrivate = isPrivate,
		)
	def deriveAccountKey(self, account):
		"""
		deriveAccountKey derives the extended key for an account according to the
		hierarchy described by BIP0044 given the master node.
				
		In particular this is the hierarchical deterministic extended key path:
		  m/44'/<coin type>'/<account>'
		"""
		# Enforce maximum account number.
		if account > MAX_ACCOUNT_NUM:
			raise ParameterRangeError("deriveAccountKey: account number greater than MAX_ACCOUNT_NUM")

		# Derive the account key as a child of the coin type key.
		return self.child(account + HARDENED_KEY_START)


	def neuter(self): # (*ExtendedKey, error)
		"""
		neuter returns a new extended public key from this extended private key.  The
		same extended key will be returned unaltered if it is already an extended
		public key.

		As the name implies, an extended public key does not have access to the
		private key, so it is not capable of signing transactions or deriving
		child extended private keys.  However, it is capable of deriving further
		child extended public keys.
		"""
		# Already an extended public key.
		if not self.isPrivate:
			return self

		# Convert it to an extended public key.  The key for the new extended
		# key will simply be the pubkey of the current extended private key.
		#
		# This is the function N((k,c)) -> (K, c) from [BIP32].
		return ExtendedKey(
			privVer = self.privVer,
			pubVer = self.pubVer,
			key = self.pubKey,
			pubKey = self.pubKey,
			chainCode = self.chainCode,
			parentFP = self.parentFP,
			depth = self.depth,
			childNum = self.childNum,
			isPrivate = False,
		)
	def string(self):
		"""
		string returns the extended key as a human-readable base58-encoded string.
		"""
		if self.key.iszero():
			raise ZeroBytesError("unexpected zero key")

		childNumBytes = ByteArray(self.childNum, length=4)
		depthByte = ByteArray(self.depth % 256, length=1)

		# The serialized format is:
		#   version (4) || depth (1) || parent fingerprint (4)) ||
		#   child num (4) || chain code (32) || key data (33) || checksum (4)
		serializedBytes = ByteArray(bytearray(0)) # length serializedKeyLen + 4 after appending
		if self.isPrivate:
			serializedBytes += self.privVer
		else:
			serializedBytes += self.pubVer

		serializedBytes += depthByte
		serializedBytes += self.parentFP
		serializedBytes += childNumBytes
		serializedBytes += self.chainCode
		if self.isPrivate:
			serializedBytes += bytearray(1)
			serializedBytes += self.key
		else:
			serializedBytes += self.pubKey

		checkSum = checksum(serializedBytes.b)[:4]
		serializedBytes += checkSum

		return b58encode(serializedBytes.bytes()).decode("ascii")

	def deriveChildAddress(self, i, net):
		child = self.child(i)
		return newAddressPubKeyHash(hash160(child.publicKey().serializeCompressed().b), net, STEcdsaSecp256k1).string()




		# pkHash = hash160(child.pubKey.b)

		# addrID = net.PubKeyHashAddrID

		# b = ByteArray(addrID)
		# b += pkHash
		# b += checksum(b.b)
		# x = b.int()

		# answer = ""

		# while x > 0:
		# 	m = x%RADIX
		# 	x = x//RADIX
		# 	answer += ALPHABET[m]

		# while len(answer) < len(b)*136//100:
		# 	answer += ALPHABET[0]

		# # reverse
		# return answer[::-1]
	def privateKey(self):
		return privKeyFromBytes(self.key)
	def publicKey(self):
		return Curve.parsePubKey(self.pubKey)

json.register(ExtendedKey)

def decodeExtendedKey(net, pw, key):
	"""
	Decode an base58 ExtendedKey using the passphrase (SecretKey or ByteArray) and network parameters.
	"""
	decoded = ByteArray(b58decode(pw.decrypt(key.bytes())))
	if len(decoded) != SERIALIZED_KEY_LENGTH+4:
		raise Exception("decoded private key is wrong length")

	# The serialized format is:
	#   version (4) || depth (1) || parent fingerprint (4)) ||
	#   child num (4) || chain code (32) || key data (33) || checksum (4)

	# Split the payload and checksum up and ensure the checksum matches.
	payload = decoded[:len(decoded)-4]
	checkSum = decoded[len(decoded)-4:]
	if checkSum != checksum(payload.b)[:4]:
		raise Exception("wrong checksum")

	# Ensure the version encoded in the payload matches the provided network.
	privVersion = net.HDPrivateKeyID
	pubVersion = net.HDPublicKeyID
	version = payload[:4]
	if version != privVersion and version != pubVersion:
		raise Exception("unknown version")

	# Deserialize the remaining payload fields.
	depth = payload[4:5].int()
	parentFP = payload[5:9]
	childNum = payload[9:13].int()
	chainCode = payload[13:45]
	keyData = payload[45:78]

	# The key data is a private key if it starts with 0x00.  Serialized
	# compressed pubkeys either start with 0x02 or 0x03.
	isPrivate = keyData[0] == 0x00
	if isPrivate:
		# Ensure the private key is valid.  It must be within the range
		# of the order of the secp256k1 curve and not be 0.
		keyData = keyData[1:]
		# if keyNum.Cmp(secp256k1.S256().N) >= 0 || keyNum.Sign() == 0 {
		if keyData >= Curve.N or keyData.iszero():
			raise Exception("unusable key")
		# Ensure the public key parses correctly and is actually on the
		# secp256k1 curve.
		Curve.publicKey(keyData.int())

	return ExtendedKey(
		privVer = privVersion, 
		pubVer = pubVersion, 
		key = keyData,
		pubKey = "",
		chainCode = chainCode, 
		parentFP = parentFP, 
		depth = depth, 
		childNum = childNum, 
		isPrivate = isPrivate,
	)


class AESCipher(object):
	"""AES encryption and decryption class from user mnothic at http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256"""
	def __init__(self): 
		self.bs = 32
	def encrypt(self, password, raw):
		key = hashlib.sha256(password).digest()
		raw = self._pad(raw)
		cipher =  pyaes.AESModeOfOperationCTR(key)
		return base64.b64encode(cipher.encrypt(raw)).decode('utf-8')
	def decrypt(self, password, enc):
		enc = base64.b64decode(enc)
		key = hashlib.sha256(password).digest()
		cipher = pyaes.AESModeOfOperationCTR(key)
		return self._unpad(cipher.decrypt(enc)).decode('utf-8')
	def _pad(self, s):
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]

AES = AESCipher()

class ScryptParams:
	def __init__(self, salt, digest, n, r, p):
		self.n = n
		self.r = r
		self.p = p
		self.salt = salt
		self.digest = digest
	def __tojson__(self):
		return {
			"n": self.n,
			"r": self.r,
			"p": self.p,
			"salt": self.salt,
			"digest": self.digest,		
		}
	@staticmethod
	def __fromjson__(obj):
		return ScryptParams(obj["salt"], obj["digest"], obj["n"], obj["r"], obj["p"])
	def __repr__(self):
		return repr(self.__tojson__())

json.register(ScryptParams)

class SecretKey:
	def __init__(self, password):
		super().__init__()
		salt = ByteArray(generateSeed(KEY_SIZE))
		n, r, p = defaultScryptParams()
		self.key = ByteArray(hashlib.scrypt(decodeBA(password), salt=salt.b, n=n, r=r, p=p, maxmem=32*1024*10224, dklen=KEY_SIZE))
		digest = ByteArray(hashlib.sha256(self.key.b).digest())
		self.keyParams = ScryptParams(salt, digest, n, r, p)
	def params(self):
		return self.keyParams
	def encrypt(self, thing):
		return self.key.encrypt(thing)
	def decrypt(self, thing):
		return self.key.decrypt(thing)
	@staticmethod
	def rekey(password, kp):
		sk = SecretKey(b"")
		sk.keyParams = kp
		sk.key = ByteArray(hashlib.scrypt(decodeBA(password), salt=kp.salt.b, n=kp.n, r=kp.r, p=kp.p, maxmem=32*1024*10224, dklen=KEY_SIZE))
		checkDigest = ByteArray(hashlib.sha256(sk.key.b).digest())
		if checkDigest != kp.digest:
			raise PasswordError("rekey digest check failed")
		return sk

class TestCrypto(unittest.TestCase):
	def test_encryption(self):
		a = SecretKey("abc".encode("ascii"))
		aEnc = a.encrypt(b'dprv3n8wmhMhC7p7QuzHn4fYgq2d87hQYAxWH3RJ6pYFrd7LAV71RcBQWrFFmSG3yYWVKrJCbYTBGiniTvKcuuQmi1hA8duKaGM8paYRQNsD1P6')
		b = SecretKey.rekey("abc".encode("ascii"), a.params())
		aUnenc = b.decrypt(aEnc.bytes())
		self.assertTrue(a, aUnenc)
	def test_curve(self):
		pass
	def test_priv_keys(self):
		key = ByteArray("eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694")
		pk = privKeyFromBytes(key)

		inHash = ByteArray("00010203040506070809")
		# sig = txscript.signRFC6979(pk.key, inHash)

		# self.assertTrue(txscript.verifySig(pk.pub, inHash, sig.r, sig.s))


