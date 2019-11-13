"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

Cryptographic functions.
"""
import hashlib
import hmac
import unittest
from tinydecred.util import tinyjson
from tinydecred.crypto.secp256k1.curve import curve as Curve, PublicKey, PrivateKey
from tinydecred.crypto.rando import generateSeed
from tinydecred.crypto.bytearray import ByteArray
from blake256.blake256 import blake_hash
from base58 import b58encode, b58decode

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
    """
    Address represents an address, which is a pubkey hash and its base-58
    encoding.
    """
    def __init__(self, netID=None, pkHash=None, net=None):
        self.netID = netID
        self.pkHash = pkHash
        self.net = net
    def string(self):
        """
        A base-58 encoding of the pubkey hash.

        Returns:
            str: The encoded address.
        """
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

def hmacDigest(key, msg, digestmod=hashlib.sha512):
    """
    Get the hmac keyed hash.

    Args:
        key (byte-like): the key
        msg (byte-like): the message
        digestmod (digest): A hashlib digest type constant.

    Returns:
        str: The secure hash of msg.
    """
    h = hmac.new(key, msg=msg, digestmod=digestmod)
    return h.digest()

def hash160(b):
    """
    A RIPEMD160 hash of the blake256 hash of the input.

    Args:
        b (byte-like): The bytes to hash.

    Returns:
        ByteArray: A 20-byte hash.
    """
    h = hashlib.new("ripemd160")
    h.update(blake_hash(b))
    return ByteArray(h.digest())

def checksum(input):
    """
    A checksum.

    Args:
        input (byte-like): Bytes to obtain a checksum for.

    Returns:
        bytes: A 4-byte checksum.
    """
    return blake_hash(blake_hash(input))[:4]

def sha256ChecksumByte(input):
    """
    This checksum byte is used for the PGP-based mnemonic seed checksum word.

    Args:
        input (byte-like): Bytes to obtain a checksum for.

    Returns:
        byte: The first byte of a double sha256 hash of input.
    """
    v = hashlib.sha256(input).digest()
    return hashlib.sha256(v).digest()[0]

def mac(key, msg):
    """
    SHA256-based message authentication code.

    Args:
        key (byte-like): Authentication key.
        msg (byte-like): Message to hash.

    Returns:
        ByteArray: The authentication hash.
    """
    return ByteArray(hmacDigest(key.bytes(), msg.bytes(), hashlib.sha256))

def egcd(a, b):
    """
    Calculate the extended Euclidean algorithm. ax + by = gcd(a,b)

    Args:
        a (int): An integer.
        b (int): Another integer.

    Returns:
        int: Greatest common denominator.
        int: x coefficient of Bezout's identity.
        int: y coefficient of Bezout's identity.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modInv(a, m):
    """
    Modular inverse based on https://stackoverflow.com/a/9758173/1124661.
    Raises an exception if impossible.

    Args:
        a (int): An integer.
        m (int): The modulus.

    Returns:
        int: The modular inverse.
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def hashH(b):
    """
    The BLAKE256 hash as a ByteArray.

    Args:
        b (byte-like): The thing to hash.

    Returns:
        ByteArray: The hash.
    """
    return ByteArray(blake_hash(b), length=BLAKE256_SIZE)

def privKeyFromBytes(pk):
    """
    PrivKeyFromBytes creates a PrivateKey for the secp256k1 curve based on
    the provided byte-encoding.

    Args:
        pk (ByteArray): The private key bytes.

    Returns:
        secp256k1.Privatekey: The private key structure.
    """
    x, y = Curve.scalarBaseMult(pk.int())
    return PrivateKey(Curve, pk, x, y)

def b58CheckDecode(s):
    """
    Decode the base-58 encoded address, parsing the version bytes and the pubkey
    hash. An exception is raised if the checksum is invalid or missing.

    Args:
        s (str): The base-58 encoded address.

    Returns:
        ByteArray: Decoded bytes minus the leading version and trailing
            checksum.
        int: The version (leading two) bytes.
    """
    decoded = b58decode(s)
    if len(decoded) < 6:
        raise Exception("decoded lacking version/checksum")
    version = decoded[:2]
    cksum =decoded[len(decoded)-4:]
    if checksum(decoded[:len(decoded)-4]) != cksum:
        raise Exception("checksum error")
    payload = decoded[2 : len(decoded)-4]
    return payload, version

def newAddressPubKeyHash(pkHash, net, algo):
    """
    newAddressPubKeyHash returns a new Address.

    Args:
        pkHash (ByteArray): The hash160 of the public key.
        net (obj): The network parameters.
        algo (int): The signature curve.

    Returns:
        Address: An address object.
    """
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
    """
    ExtendedKey houses all the information needed to support a BIP0044
    hierarchical deterministic extended key.
    """
    def __init__(self, privVer, pubVer, key, pubKey, chainCode, parentFP, depth, childNum, isPrivate):
        """
        Args:
            privVer (byte-like): Network version bytes for extended priv keys.
            pubVer (byte-like): Network version bytes for extended pub keys.
            key (byte-like): The key.
            pubKey (byte-like): Will be the same as `key` for public key. Will
                be generated from key if zero is provided.
            chainCode (byte-like): Chain code for key derivation.
            parentFP (ByteArray): parent key fingerprint.
            depth (int): Key depth.
            childNum (int): Child number.
            isPrivate (bool): Whether the key is a private or public key.
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
    # def __tojson__(self):
    #     return {
    #         "privVer": self.privVer,
    #         "pubVer": self.pubVer,
    #         "key": self.key,
    #         "pubKey": self.pubKey,
    #         "chainCode": self.chainCode,
    #         "parentFP": self.parentFP,
    #         "depth": self.depth,
    #         "childNum": self.childNum,
    #         "isPrivate": self.isPrivate,
    #     }
    # @staticmethod
    # def __fromjson__(obj):
    #     return ExtendedKey(
    #         privVer = obj["privVer"],
    #         pubVer = obj["pubVer"],
    #         key = obj["key"],
    #         pubKey = obj["pubKey"],
    #         chainCode = obj["chainCode"],
    #         parentFP = obj["parentFP"],
    #         depth = obj["depth"],
    #         childNum = obj["childNum"],
    #         isPrivate = obj["isPrivate"],
    #     )
    def deriveCoinTypeKey(self, coinType):
        """
        First two hardened child derivations in accordance with BIP0044.

        Args:
            coinType (int): The BIP0044 coin type. For a full list, see
                https://github.com/satoshilabs/slips/blob/master/slip-0044.md

        Returns:
            ExtendedKey: The coin-type key.
        """
        if coinType > MAX_COIN_TYPE:
            raise ParameterRangeError("coinType too high. %i > %i" % (coinType, MAX_COIN_TYPE))

        purpose = self.child(44 + HARDENED_KEY_START)

        # Derive the purpose key as a child of the master node.
        return purpose.child(coinType + HARDENED_KEY_START)
    def child(self, i):
        """
        Child returns a derived child extended key at the given index.  When
        this extended key is a private extended key (as determined by the
        IsPrivate function (TODO: implement IsPrivate)), a private extended key
        will be derived. Otherwise, the derived extended key will also be a
        public extended key.

        When the index is greater than or equal to the HardenedKeyStart
        constant, the derived extended key will be a hardened extended key. It
        is only possible to derive a hardended extended key from a private
        extended key. Consequently, this function will throw an exception if a
        hardened child extended key is requested from a public extended key.

        A hardened extended key is useful since, as previously mentioned, it
        requires a parent private extended key to derive. In other words, normal
        child extended public keys can be derived from a parent public extended
        key (no knowledge of the parent private key) whereas hardened extended
        keys may not be.

        NOTE: There is an extremely small chance (< 1 in 2^127) the specific
        child index does not derive to a usable child. An exception will happen
        if this should occur, and the caller is expected to ignore the invalid
        child and simply increment to the next index.

        There are four scenarios that could happen here:
        1) Private extended key -> Hardened child private extended key
        2) Private extended key -> Non-hardened child private extended key
        3) Public extended key -> Non-hardened child public extended key
        4) Public extended key -> Hardened child public extended key (INVALID!)

        Args:
            i (int): Child number.

        Returns:
            ExtendedKey: The child key.
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

        data |= i # ByteArray will handle the type conversion.

        # Take the HMAC-SHA512 of the current key's chain code and the derived
        # data:
        #   I = HMAC-SHA512(Key = chainCode, Data = data)
        ilr = ByteArray(hmacDigest(self.chainCode.b, data.b, hashlib.sha512))

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
        deriveAccountKey derives the extended key for an account according to
        the hierarchy described by BIP0044 given the master node.

        In particular this is the hierarchical deterministic extended key path:
          m/44'/<coin type>'/<account>'

        Args:
            account (int): Account number.

        Returns:
            ExtendedKey: Account key.
        """
        # Enforce maximum account number.
        if account > MAX_ACCOUNT_NUM:
            raise ParameterRangeError("deriveAccountKey: account number greater than MAX_ACCOUNT_NUM")

        # Derive the account key as a child of the coin type key.
        return self.child(account + HARDENED_KEY_START)
    def neuter(self):
        """
        neuter returns a new extended public key from this extended private key.
        The same extended key will be returned unaltered if it is already an
        extended public key.

        As the name implies, an extended public key does not have access to the
        private key, so it is not capable of signing transactions or deriving
        child extended private keys. However, it is capable of deriving further
        child extended public keys.

        Returns:
            ExtendedKey: The public extended key.
        """
        # Already an extended public key.
        if not self.isPrivate:
            return self

        # Convert it to an extended public key. The key for the new extended
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
        string returns the extended key as a base58-encoded string. See
        `decodeExtendedKey` for decoding.

        Returns:
            str: The encoded extended key.
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
        return b58encode(serializedBytes.bytes()).decode()
    def deriveChildAddress(self, i, net):
        """
        The base-58 encoded address for the i'th child.

        Args:
            i (int): Child number.
            net (obj): Network parameters.

        Returns:
            Address: Child address.
        """
        child = self.child(i)
        return newAddressPubKeyHash(hash160(child.publicKey().serializeCompressed().b), net, STEcdsaSecp256k1).string()
    def privateKey(self):
        """
        A PrivateKey structure that can be used for signatures.

        Returns:
            secp256k1.PrivateKey: The private key structure.
        """
        return privKeyFromBytes(self.key)
    def publicKey(self):
        """
        A PublicKey structure of the pubKey.

        Returns:
            secp256k1.PublicKey: The public key structure.
        """
        return Curve.parsePubKey(self.pubKey)

# tinyjson.register(ExtendedKey)

def decodeExtendedKey(net, pw, key):
    """
    Decode an base58 ExtendedKey using the passphrase and network parameters.

    Args:
        pw (SecretKey or ByteAray): The encryption key.
        key (str): Base-58 encoded extended key.

    Returns:
        ExtendedKey: The decoded key.
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

    # The key data is a private key if it starts with 0x00. Serialized
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
DEFAULT_KDF_PARAMS = {
    "func": "pbkdf2_hmac",
    "iterations": 100000,
    "hash_name": "sha256",
}

def defaultKDFParams():
    """
    Default parameters for the key derivation function.

    Returns:
        str: hmac function name.
        str: hmac hash type name.
        int: Number of iterations.
    """
    d = DEFAULT_KDF_PARAMS
    return d["func"], d["hash_name"], d["iterations"]

class KDFParams(object):
    """
    Parameters for the key derivation function, including the function used.
    """
    def __init__(self, salt, digest):
        func, hn, its = defaultKDFParams()
        self.kdfFunc = func
        self.hashName = hn
        self.salt = salt
        self.digest = digest
        self.iterations = its
    def __tojson__(self):
        return {
            "kdfFunc": self.kdfFunc,
            "hashName": self.hashName,
            "salt": self.salt,
            "digest": self.digest,
            "iterations": self.iterations,
        }
    @staticmethod
    def __fromjson__(obj):
        p = KDFParams(
            salt = obj["salt"],
            digest = obj["digest"],
        )
        p.iterations = obj["iterations"]
        p.hashName = obj["hashName"]
        p.kdfFunc = obj["kdfFunc"]
        return p
    def __repr__(self):
        return repr(self.__tojson__())
tinyjson.register(KDFParams)

class ScryptParams(object):
    """
    A set of scrypt parameters. Can be stored and retreived in plain text to
    regenerate encryption keys.
    """
    def __init__(self, salt, digest, n, r, p):
        """
        Args:
            salt (ByteArray): A randomized salt.
            digest: Key hash used as a checksum.
            n (int): Scrypt iteration count, N.
            r (int): Scrypt memory factor, r.
            p (int): Scrypt parallelization factor, p.
        """
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

tinyjson.register(ScryptParams)

class SecretKey(object):
    """
    SecretKey is a password-derived key that can be used for encryption and
    decryption.
    """
    def __init__(self, pw):
        """
        Args:
            pw (byte-like): A password that deterministically generates the key.
        """
        super().__init__()
        salt = ByteArray(generateSeed(KEY_SIZE))
        b = lambda v: ByteArray(v).bytes()
        func, hashName, iterations = defaultKDFParams()
        self.key = ByteArray(hashlib.pbkdf2_hmac(hashName, b(pw), salt.bytes(), iterations))
        digest = ByteArray(hashlib.sha256(self.key.b).digest())
        self.keyParams = KDFParams(salt, digest)
    def params(self):
        """
        The key params can be stored in plain text. They must be provided to
        `rekey` to regenerate a key.

        Returns:
            KDFParams: The hash parameters and salt used to generate the key.
        """
        return self.keyParams
    def encrypt(self, thing):
        """
        Encrypt the input using the key.

        Args:
            thing (byte-like): The thing to encrypt.

        Returns:
            ByteArray: The thing, encrypted.
        """
        return self.key.encrypt(thing)
    def decrypt(self, thing):
        """
        Decrypt the input using the key.

        Args:
            thing (byte-like): The thing to decrypt.

        Returns:
            ByteArray: The thing, decrypted.
        """
        return self.key.decrypt(thing)
    @staticmethod
    def rekey(password, kp):
        """
        Regenerate a key using its origin key parameters, as returned by
        `params`.

        Args:
            kp (KDFParams): The key parameters from the original generation
                of the key being regenerated.

        Returns:
            SecretKey: The regenerated key.
        """
        sk = SecretKey(b"")
        sk.keyParams = kp
        b = lambda v: ByteArray(v).bytes()
        func = kp.kdfFunc
        if func == "pbkdf2_hmac":
            sk.key = ByteArray(hashlib.pbkdf2_hmac(kp.hashName, b(password), b(kp.salt), kp.iterations))
        else:
            raise Exception("unkown key derivation function")
        checkDigest = ByteArray(hashlib.sha256(sk.key.b).digest())
        if checkDigest != kp.digest:
            raise PasswordError("rekey digest check failed")
        return sk

class TestCrypto(unittest.TestCase):
    def test_encryption(self):
        '''
        Test encryption and decryption.
        '''
        a = SecretKey("abc".encode())
        aEnc = a.encrypt(b'dprv3n8wmhMhC7p7QuzHn4fYgq2d87hQYAxWH3RJ6pYFrd7LAV71RcBQWrFFmSG3yYWVKrJCbYTBGiniTvKcuuQmi1hA8duKaGM8paYRQNsD1P6')
        b = SecretKey.rekey("abc".encode(), a.params())
        aUnenc = b.decrypt(aEnc.bytes())
        self.assertTrue(a, aUnenc)
    def test_curve(self):
        '''
        Test curves. Unimplemented.
        '''
        pass
    def test_priv_keys(self):
        '''
        Test private key parsing.
        '''
        key = ByteArray("eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694")
        pk = privKeyFromBytes(key)

        inHash = ByteArray("00010203040506070809")
        # sig = txscript.signRFC6979(pk.key, inHash)

        # self.assertTrue(txscript.verifySig(pk.pub, inHash, sig.r, sig.s))
