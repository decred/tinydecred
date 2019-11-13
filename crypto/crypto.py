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
RIPEMD160_SIZE = 20
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

# PKFUncompressed indicates the pay-to-pubkey address format is an
# uncompressed public key.
PKFUncompressed = 0

# PKFCompressed indicates the pay-to-pubkey address format is a
# compressed public key.
PKFCompressed = 1

class ParameterRangeError(Exception):
    pass
class ZeroBytesError(Exception):
    pass
class PasswordError(Exception):
    pass

def encodeAddress(netID, k):
    b = ByteArray(netID)
    b += k
    b += checksum(b.b)
    return b58encode(b.bytes()).decode()

class AddressPubKeyHash:
    """
    AddressPubKeyHash represents an address based on a pubkey hash.
    """
    def __init__(self, netID=None, pkHash=None, sigType=STEcdsaSecp256k1):
        if len(pkHash) != 20:
            raise Exception("AddressPubKeyHash expected 20 bytes, got %d" % len(pkHash))
        # For now, just reject anything except secp256k1
        if sigType != STEcdsaSecp256k1:
            raise Exception("unsupported signature type %v", self.sigType)
        self.sigType = sigType
        self.netID = netID
        self.pkHash = pkHash
    def string(self):
        """
        A base-58 encoding of the pubkey hash.

        Returns:
            str: The encoded address.
        """
        return encodeAddress(self.netID, self.pkHash)
    def address(self):
        return self.string()
    def scriptAddress(self):
        return self.pkHash.copy()
    def hash160(self):
        return self.pkHash.copy()

class AddressSecpPubKey:
    """
    AddressSecpPubKey represents and address, which is a pubkey hash and it's
    base-58 encoding. Argument pubkey should be a ByteArray corresponding the
    the serializedCompressed public key (33 bytes).
    """
    def __init__(self, serializedPubkey, net):
        pubkey = Curve.parsePubKey(serializedPubkey)
        # Set the format of the pubkey.  This probably should be returned
        # from dcrec, but do it here to avoid API churn.  We already know the
        # pubkey is valid since it parsed above, so it's safe to simply examine
        # the leading byte to get the format.
        fmt = serializedPubkey[0]
        if fmt in (0x02, 0x03):
            pkFormat = PKFCompressed
        elif fmt == 0x04:
            pkFormat = PKFUncompressed
        else:
            raise Exception("unknown pubkey format %d", fmt)
        self.pubkeyFormat = pkFormat
        self.netID = self.pubkeyID = net.PubKeyAddrID
        self.pubkeyHashID = net.PubKeyHashAddrID
        self.pubkey = pubkey
    def serialize(self):
        """
        serialize returns the serialization of the public key according to the
        format associated with the address.
        """
        fmt = self.pubkeyFormat
        if fmt == PKFUncompressed:
            return self.pubkey.serializeUncompressed()
        elif fmt == PKFCompressed:
            return self.pubkey.serializeCompressed()
        raise Exception("unknown pubkey format")
    def string(self):
        """
        A base-58 encoding of the pubkey.

        Returns:
            str: The encoded address.
        """
        encoded = ByteArray(self.pubkeyID)
        buf = ByteArray(STEcdsaSecp256k1, length=1)
        compressed = self.pubkey.serializeCompressed()
        # set the y-bit if needed
        if compressed[0] == 0x03:
            buf[0] |= (1 << 7)
        buf += compressed[1:]
        encoded += buf
        encoded += checksum(encoded.b)
        return b58encode(encoded.bytes()).decode()
    def address(self):
        """
        Address returns the string encoding of the public key as a
        pay-to-pubkey-hash.  Note that the public key format (uncompressed,
        compressed, etc) will change the resulting address.  This is expected since
        pay-to-pubkey-hash is a hash of the serialized public key which obviously
        differs with the format.  At the time of this writing, most Decred addresses
        are pay-to-pubkey-hash constructed from the compressed public key.
        """
        return encodeAddress(self.pubkeyHashID, hash160(self.serialize().bytes()))
    def scriptAddress(self):
        return self.serialize()
    def hash160(self):
        return hash160(self.serialize().bytes())

class AddressScriptHash(object):
    """
    AddressScriptHash is an Address for a pay-to-script-hash (P2SH) transaction.
    """
    def __init__(self, netID, scriptHash):
        self.netID = netID
        self.scriptHash = scriptHash
    @staticmethod
    def fromScript(netID, script):
        return AddressScriptHash(netID, hash160(script.b))
    def string(self):
        """
        A base-58 encoding of the pubkey hash.

        Returns:
            str: The encoded address.
        """
        return encodeAddress(self.netID, self.scriptHash)
    def address(self):
        """
        Address returns the string encoding of a pay-to-script-hash address.
        """
        return self.string()
    def scriptAddress(self):
        return self.scriptHash.copy()
    def hash160(self):
        return self.scriptHash.copy()

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
        byte-like: A 20-byte hash.
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
    payload = ByteArray(decoded[2 : len(decoded)-4])
    return payload, version

def newAddressPubKey(decoded, net):
    """
    NewAddressPubKey returns a new Address. decoded must be 33 bytes. This
    constructor takes the decoded pubkey such as would be decoded from a base58
    string. The first byte indicates the signature suite. For compressed
    secp256k1 pubkeys, use AddressSecpPubKey directly.
    """
    if len(decoded) == 33:
        # First byte is the signature suite and ybit.
        suite = decoded[0]
        suite &= ~(1 << 7)
        ybit = not (decoded[0]&(1<<7) == 0)
        toAppend = 0x02
        if ybit:
            toAppend = 0x03

        if suite == STEcdsaSecp256k1:
            b = ByteArray(toAppend) + decoded[1:]
            return AddressSecpPubKey(b, net)
        elif suite == STEd25519:
            # return NewAddressEdwardsPubKey(decoded, net)
            raise Exception("Edwards signatures not implemented")
        elif suite == STSchnorrSecp256k1:
            # return NewAddressSecSchnorrPubKey(append([]byte{toAppend}, decoded[1:]...), net)
            raise Exception("Schnorr signatures not implemented")
        else:
            raise Exception("unknown address type %d" % suite)
    raise Exception("unable to decode pubkey of length %d" % len(decoded))

def newAddressPubKeyHash(pkHash, net, algo):
    """
    newAddressPubKeyHash returns a new AddressPubkeyHash.

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
        # netID = net.PKHEdwardsAddrID
        raise Exception("Edwards not implemented")
    elif algo == STSchnorrSecp256k1:
        # netID = net.PKHSchnorrAddrID
        raise Exception("Schnorr not implemented")
    else:
        raise Exception("unknown ECDSA algorithm")
    return AddressPubKeyHash(netID, pkHash)

def newAddressScriptHash(script, net):
    """
    newAddressScriptHash returns a new AddressScriptHash from a redeem script.

    Args:
        script (ByteArray): the redeem script
        net (obj): the network parameters

    Returns:
        AddressScriptHash: An address object.
    """
    return newAddressScriptHashFromHash(hash160(script.b), net)

def newAddressScriptHashFromHash(scriptHash, net):
    """
    newAddressScriptHashFromHash returns a new AddressScriptHash from an already
    hash160'd script.

    Args:
        pkHash (ByteArray): The hash160 of the public key.
        net (obj): The network parameters.

    Returns:
        AddressScriptHash: An address object.
    """
    if len(scriptHash) != RIPEMD160_SIZE:
        raise Exception("incorrect script hash length")
    return AddressScriptHash(net.ScriptHashAddrID, scriptHash)

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
    def test_addr_pubkey(self):
        from tinydecred.pydecred import mainnet
        pairs = [
            ("033b26959b2e1b0d88a050b111eeebcf776a38447f7ae5806b53c9b46e07c267ad", "DkRKjw7LmGCSzBwaUtjQLfb75Zcx9hH8yGNs3qPSwVzZuUKs7iu2e"),
            ("0389ced3eaee84d5f0d0e166f6cd15f1bf6f429d1d13709393b418a6fb22d8be53", "DkRLLaJWkmH75iZGtQYE6FEf16zxeHr6TCAF59tGxhds4MFc2HqUS"),
            ("02a14a0023d7d8cbc5d39fa60f7e4dc4d5bf18a7031f52875fbca6bf837f68713f", "DkM3hdWuKSSTm7Vq8WZx5f294vcZbPkAQYBDswkjmF1CFuWCRYxTr"),
            ("03c3e3d7cde1c453a6283f5802a73d1cb3827cb4b007f58e3a52a36ce189934b6a", "DkRLn9vzsjK4ZYgDKy7JVYHKGvpZU5CYGK9H8zF2VCWbpTyVsEf4P"),
            ("0254e17b230e782e591a9910794fdbf9943d500a47f2bf8446e1238f84e809bffc", "DkM37ymaat9j6oTFii1MZVpXrc4aRLEMHhTZrvrz8QY6BZ2HX843L"),
        ]
        for hexKey, addrStr in pairs:
            addr = AddressSecpPubKey(ByteArray(hexKey), mainnet)
            self.assertEqual(addr.string(), addrStr)
    def test_addr_pubkey_hash(self):
        from tinydecred.pydecred import mainnet
        pairs = [
            ("e201ee2f37bcc0ba0e93f82322e48333a92b9355", "DsmZvWuokf5NzFwFfJk5cALZZBZivjkhMSQ"),
            ("5643d59202de158b509544d40b32e85bfaf6243e", "DsYq2s8mwpM6vXLbjb8unhNmBXFofPzcrrv"),
            ("c5fa0d15266e055eaf8ec7c4d7a679885266ef0d", "Dsj1iA5PBCU6Nmpe6jqucwfHK17WmSKd3uG"),
            ("73612f7b7b1ed32ff44dded7a2cf87c206fabf8a", "DsbUyd4DueVNyvfh542kZDXNEGKByUAi1RV"),
            ("a616bc09179e31e6d9e3abfcb16ac2d2baf45141", "Dsg76ttvZmTFchZ5mWRnAUg6UGfCyrq86ch"),
        ]
        for pubkeyHash, addrStr in pairs:
            addr = AddressPubKeyHash(mainnet.PubKeyHashAddrID, ByteArray(pubkeyHash))
            self.assertEqual(addr.string(), addrStr)
    def test_addr_script_hash(self):
        from tinydecred.pydecred import mainnet
        pairs = [
            ("52fdfc072182654f163f5f0f9a621d729566c74d", "Dcf2QjJ1pSnLwthhw1cwE55MVZNQVXDZWQT"),
            ("10037c4d7bbb0407d1e2c64981855ad8681d0d86", "DcYvG3fPxHDZ5pzW8nj4rcYq5kM9XFxXpUy"),
            ("d1e91e00167939cb6694d2c422acd208a0072939", "DcrbVYmhm5yX9mw9qdwUVWw6psUhPGrQJsT"),
            ("487f6999eb9d18a44784045d87f3c67cf22746e9", "Dce4vLzzENaZT7D2Wq5crRZ4VwfYMDMWkD9"),
            ("95af5a25367951baa2ff6cd471c483f15fb90bad", "Dcm73og7Hn9PigaNu59dHgKnNSP1myCQ39t"),
        ]
        for scriptHash, addrStr in pairs:
            addr = newAddressScriptHashFromHash(ByteArray(scriptHash), mainnet)
            self.assertEqual(addr.string(), addrStr)
