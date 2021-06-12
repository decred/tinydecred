"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details

Cryptographic functions.
"""

from typing import ByteString, Union, Optional, Tuple
import hashlib

from base58 import b58encode, b58decode
import bech32

from decred import DecredError
from decred.crypto.crypto import (
    RIPEMD160_SIZE,
    PKFCompressed,
    PKFUncompressed,
    PKFHybrid,
)
from decred.crypto.secp256k1.curve import curve as Secp256k1, PrivateKey
from decred.btc import nets
from decred.util.encode import BuildyBytes, ByteArray, decodeBlob, unblobCheck


PubKeyBytesLenCompressed = 33
PubKeyBytesLenUncompressed = 65
PubKeyBytesLenHybrid = 65
pubkeyCompressed = 0x2  # y_bit + x coord
pubkeyUncompressed = 0x4  # x coord + y coord
pubkeyHybrid = 0x6  # y_bit + x coord + y coord
PrivKeyBytesLen = 32
compressMagic = 0x01


class Address:
    """
    A parent class for all addresses. This class specifies an API that all
    child classes should implement.
    """

    def __init__(self, netParams):
        """
        Args:
            chainParams (module): The network parameters.
        """
        self.netName = netParams.Name

    @staticmethod
    def blob(addr: 'Address'):
        """Satisfies the encode.Blobber API"""
        aEnc = addr.string().encode()
        netEnc = addr.netName.encode()
        return BuildyBytes(0).addData(netEnc).addData(aEnc).b

    @staticmethod
    def unblob(b: Union[ByteString, ByteArray]):
        """Satisfies the encode.Blobber API"""
        ver, d = decodeBlob(b)
        unblobCheck("Address", ver, len(d), {0: 2})
        return decodeAddress(d[1].decode(), nets.parse(d[0].decode()))

    def __eq__(self, a: 'Address'):
        """Check that other address is equivalent to this address."""
        raise NotImplementedError("__eq__ must be implemented by child class")

    def string(self) -> str:
        """
        The base-58 encoding of the address.

        Note that string() differs subtly from address(): string() will return
        the value as a string without any conversion, while address() may
        convert destination types (for example, converting pubkeys to P2PKH
        addresses) before encoding as a payment address string.

        Returns:
            str: The encoded address.
        """
        raise NotImplementedError("string must be implemented by child class")

    def encodeAddress(self) -> str:
        """
        encodeAddress returns the string encoding of the payment address
        associated with the Address value.  See the comment on string for how
        this method differs from string.

        Returns:
            str: The encoded address.
        """

        raise NotImplementedError("encodeAddress must be implemented by child class")

    def scriptAddress(self) -> ByteArray:
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """

        raise NotImplementedError("scriptAddress must be implemented by child class")

    def isForNet(self, chainParams: object) -> bool:
        """
        isForNet returns whether or not the address is associated with the
        passed bitcoin network.

        Returns:
            bool: True if address is for the supplied network.
        """

        raise NotImplementedError("isForNet must be implemented by child class")


class AddressPubKeyHash(Address):
    """
    Address based on a pubkey hash.
    """

    def __init__(self, pkHash: Optional[ByteArray] = None, netParams: Optional[object] = None):
        """
        Args:
            pkHash (ByteArray): The hashed pubkey.
            netParams (module): The network parameters.
        """
        super().__init__(netParams)
        pkh_len = len(pkHash)
        if pkh_len != RIPEMD160_SIZE:
            raise DecredError(
                f"AddressPubKeyHash expected {RIPEMD160_SIZE} bytes, got {pkh_len}"
            )

        self.netID = netParams.PubKeyHashAddrID
        self.pkHash = pkHash

    def __eq__(self, a: Union[str, Address]) -> bool:
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a == self.string()
        elif isinstance(a, AddressPubKeyHash):
            return (
                a.pkHash == self.pkHash
                and a.netID == self.netID
            )
        return False

    def string(self) -> str:
        """
        A base-58 encoding of the pubkey hash.

        Returns:
            str: The encoded address.
        """
        return encodeAddressBase58(self.pkHash, self.netID)

    def encodeAddress(self) -> str:
        """
        The string encoding of a pay-to-pubkey-hash address.

        Returns:
            str: The encoded address.
        """
        return self.string()

    def scriptAddress(self) -> ByteArray:
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.pkHash.copy()

    def isForNet(self, chainParams: object) -> bool:
        """
        isForNet returns whether or not the address is associated with the
        passed bitcoin network.

        Returns:
            bool: True if address is for the supplied network.
        """
        return self.netID == chainParams.PubKeyHashAddrID

    def hash160(self) -> ByteArray:
        """
        For AddressPubKeyHash, hash160 is the same as scriptAddress.

        Returns:
            ByteArray: The hash.
        """
        return self.pkHash.copy()


class AddressScriptHash(Address):
    """
    AddressScriptHash is an Address for a pay-to-script-hash (P2SH) transaction.
    """

    def __init__(self, scriptHash, netParams):

        if len(scriptHash) != RIPEMD160_SIZE:
            raise DecredError(f"incorrect script hash length {len(scriptHash)}")

        super().__init__(netParams)
        self.netID = netParams.ScriptHashAddrID
        self.scriptHash = scriptHash

    @staticmethod
    def fromScript(script, netParams):
        """
        Create a new AddressScriptHash from a redeem script.

        Args:
            script (ByteArray): the redeem script
            netParams (module): the network parameters

        Returns:
            AddressScriptHash: An address object.
        """
        return AddressScriptHash(hash160(script.b), netParams)

    def __eq__(self, a: Union[str, Address]) -> bool:
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a == self.string()
        elif isinstance(a, AddressScriptHash):
            return a.scriptHash == self.scriptHash and a.netID == self.netID
        return False

    def string(self) -> str:
        """
        A base-58 encoding of the pubkey hash.

        Returns:
            str: The encoded address.
        """
        return encodeAddressBase58(self.scriptHash, self.netID)

    def encodeAddress(self) -> str:
        """
        The string encoding of a pay-to-pubkey-hash address.

        Returns:
            str: The encoded address.
        """
        return self.string()

    def scriptAddress(self) -> ByteArray:
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.scriptHash.copy()

    def isForNet(self, chainParams: object) -> bool:
        """
        isForNet returns whether or not the address is associated with the
        passed bitcoin network.

        Returns:
            bool: True if address is for the supplied network.
        """
        return self.netID == chainParams.ScriptHashAddrID

    def hash160(self) -> ByteArray:
        """
        For AddressPubKeyHash, hash160 is the same as scriptAddress.

        Returns:
            ByteArray: The hash.
        """
        return self.scriptHash.copy()


class AddressPubKey(Address):
    """
    An address based on an unhashed public key.
    """

    def __init__(self, serializedPubkey, netParams):
        """
        Args:
            serializedPubkey (ByteArray): Corresponds to the serialized
                compressed public key (33 bytes).
            netParams (module): The network parameters.
        """
        super().__init__(netParams)

        pubkey = Secp256k1.parsePubKey(serializedPubkey)
        # Set the format of the pubkey.  We already know the pubkey is valid
        # since it parsed above, so it's safe to simply examine the leading
        # byte to get the format.

        pkFormat = PKFUncompressed
        fmt = serializedPubkey[0]
        if fmt in (0x02, 0x03):
            pkFormat = PKFCompressed
        elif fmt in (0x06, 0x07):
            pkFormat = PKFHybrid

        self.pubkeyFormat = pkFormat
        self.netID = netParams.PubKeyHashAddrID
        self.pubkeyHashID = netParams.PubKeyHashAddrID
        self.pubkey = pubkey

    def __eq__(self, a):
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a == self.encodeAddress() or a == self.string()
        elif isinstance(a, AddressPubKey):
            return self.pubkey.serializeCompressed() == a.pubkey.serializeCompressed()
        return False

    def serialize(self):
        """
        The serialization of the public key according to the format associated
        with the address.

        Returns:
            ByteArray: The serialized publid key.
        """
        fmt = self.pubkeyFormat
        if fmt == PKFUncompressed:
            return self.pubkey.serializeUncompressed()
        elif fmt == PKFCompressed:
            return self.pubkey.serializeCompressed()
        elif fmt == PKFHybrid:
            return self.pubkey.serializeHybrid()
        raise NotImplementedError(f"unknown pubkey format {fmt}")

    def string(self):
        """
        A base-58 encoding of the pubkey.

        Returns:
            str: The encoded address.
        """
        return self.serialize().hex()

    def encodeAddress(self):
        """
        The string encoding of the public key as a pay-to-pubkey-hash.  Note
        that the public key format (uncompressed, compressed, etc) will change
        the resulting address.  This is expected since pay-to-pubkey-hash is a
        hash of the serialized public key which obviously differs with the
        format.  At the time of this writing, most Decred addresses are
        pay-to-pubkey-hash constructed from the compressed public key.

        Returns:
            str: base-58 encoded p2pkh address.
        """
        return encodeAddressBase58(hash160(self.serialize().bytes()), self.pubkeyHashID)

    def scriptAddress(self):
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.serialize()

    def isForNet(self, netParams: object) -> bool:
        """
        isForNet returns whether or not the address is associated with the
        passed bitcoin network.

        Returns:
            bool: True if address is for the supplied network.
        """
        return self.netID == netParams.PubKeyHashAddrID

    def hash160(self):
        """
        The hash160 of the serialized pubkey.

        Returns:
            ByteArray: The hash.
        """
        return hash160(self.serialize().bytes())

    def addressPubKeyHash(self) -> AddressPubKeyHash:
        """
        AddressPubKeyHash returns the pay-to-pubkey address converted to a
        pay-to-pubkey-hash address.  Note that the public key format (uncompressed,
        compressed, etc) will change the resulting address.  This is expected since
        pay-to-pubkey-hash is a hash of the serialized public key which obviously
        differs with the format.  At the time of this writing, most Bitcoin addresses
        are pay-to-pubkey-hash constructed from the uncompressed public key.
        """
        return AddressPubKeyHash(self.hash160(), self.pubkeyHashID)


class AddressWitnessPubKeyHash(Address):
    """
    Address based on a witness pubkey hash.
    """

    def __init__(self, witnessProg: ByteArray, netParams: object):
        """
        Args:
            witnessProg (ByteArray): The witness program. Just the pubkey hash.
            hrp (module or str): The bech32 prefix or the network parameters.
        """
        super().__init__(netParams)
        self.hrp = netParams.Bech32HRPSegwit
        self.witnessVersion = 0
        self.witnessProgram = witnessProg

    def __eq__(self, a: Union[str, Address]) -> bool:
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a.lower() == self.string()
        elif isinstance(a, AddressWitnessPubKeyHash):
            return (
                a.witnessProgram == self.witnessProgram
                and a.hrp == self.hrp
                and a.witnessVersion == self.witnessVersion
            )
        return False

    def encodeAddress(self) -> str:
        """
        The string encoding of a pay-to-witness-pubkey-hash address.

        Returns:
            str: The encoded address.
        """
        return encodeSegWitAddress(self.hrp, self.witnessVersion, self.witnessProgram)

    def scriptAddress(self) -> ByteArray:
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.witnessProgram

    def isForNet(self, chainParams: object) -> bool:
        """
        isForNet returns whether or not the address is associated with the
        passed bitcoin network.

        Returns:
            bool: True if address is for the supplied network.
        """
        return self.hrp == chainParams.Bech32HRPSegwit

    def string(self) -> str:
        """
        A bech32 encoding of the pubkey.

        Returns:
            str: The encoded address.
        """
        return self.encodeAddress()

    def hash160(self) -> ByteArray:
        """
        The hash160 of the serialized pubkey.

        Returns:
            ByteArray: The hash.
        """
        return self.witnessProgram


class AddressWitnessScriptHash(Address):
    """
    Address based on a witness script hash.
    """

    def __init__(self, witnessProg: ByteArray, netParams: object):
        """
        Args:
            witnessProg (ByteArray): The witness program. Just the pubkey hash.
            hrp (module or str): The bech32 prefix or the network parameters.
        """
        super().__init__(netParams)
        if len(witnessProg) != 32:
            raise DecredError(f"witness program must be 32 bytes for p2wsh. got {len(witnessProg)}")

        self.hrp = netParams.Bech32HRPSegwit
        self.witnessProgram = witnessProg
        self.witnessVersion = 0

    def __eq__(self, a: Union[str, Address]) -> bool:
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a.lower() == self.string()
        elif isinstance(a, AddressWitnessScriptHash):
            return (
                a.witnessProgram == self.witnessProgram and
                a.hrp == self.hrp and
                a.witnessVersion == self.witnessVersion
            )
        return False

    def encodeAddress(self) -> str:
        """
        The string encoding of a pay-to-witness-script-hash address.

        Returns:
            str: The encoded address.
        """
        return encodeSegWitAddress(self.hrp, self.witnessVersion, self.witnessProgram)

    def scriptAddress(self) -> ByteArray:
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.witnessProgram

    def isForNet(self, chainParams: object) -> bool:
        """
        isForNet returns whether or not the address is associated with the
        passed bitcoin network.

        Returns:
            bool: True if address is for the supplied network.
        """
        return self.hrp == chainParams.Bech32HRPSegwit

    def string(self) -> str:
        """
        A bech32 encoding of the script-hash.

        Returns:
            str: The encoded address.
        """
        return self.encodeAddress()


class WIF:
    def __init__(self, privKey: PrivateKey, compressPubKey: bool, netID: Union[object, int]):
        if hasattr(netID, "PrivateKeyID"):
            netID = netID.PrivateKeyID
        self.privKey = privKey
        self.compressPubKey = compressPubKey
        self.netID = netID

    def dict(self) -> dict:
        return dict(
            privKey=self.privKey.key.hex(),
            compressPubKey=self.compressPubKey,
        )

    @staticmethod
    def decode(wif: str) -> 'WIF':
        decoded = ByteArray(b58decode(wif))
        decodedLen = len(decoded)
        compress = False

        # Length of base58 decoded WIF must be 32 bytes + an optional 1 byte
        # (0x01) if compressed, plus 1 byte for netID + 4 bytes of checksum.
        if decodedLen == 1 + PrivKeyBytesLen + 1 + 4:
            if decoded[33] != compressMagic:
                raise DecredError("malformed 38-byte private key")
            compress = True
        elif decodedLen != 1 + PrivKeyBytesLen + 4:
            raise DecredError("malformed private key")

        # Checksum is first four bytes of double SHA256 of the identifier byte
        # and privKey.  Verify this matches the final 4 bytes of the decoded
        # private key.
        if compress:
            tosum = decoded[:1+PrivKeyBytesLen+1]
        else:
            tosum = decoded[:1+PrivKeyBytesLen]

        cksum = checksum(tosum.b)
        if cksum != decoded[decodedLen-4:]:
            raise DecredError("checksum mismatch")

        netID = decoded[0]
        privKeyBytes = decoded[1: 1+PrivKeyBytesLen]
        privKey = PrivateKey.fromBytes(privKeyBytes)
        return WIF(privKey=privKey, compressPubKey=compress, netID=netID)

    def isForNet(self, netParams: object) -> bool:
        return self.netID == netParams.PrivateKeyID

    def string(self) -> str:
        a = ByteArray(self.netID)
        # Pad and append bytes manually, instead of using Serialize, to
        # avoid another call to make.
        a += ByteArray(self.privKey.key, length=PrivKeyBytesLen)
        if self.compressPubKey:
            a += compressMagic

        a += checksum(a.b)
        return b58encode(a.b).decode("utf-8")

    def serializePubKey(self) -> ByteArray:
        if self.compressPubKey:
            return self.privKey.pub.serializeCompressed()
        return self.privKey.pub.serializeUncompressed()


def encodeAddressBase58(k, netID):
    """
    Base-58 encode the number, with the netID prepended byte-wise.

    Args:
        k (ByteArray): The pubkey or pubkey-hash or script-hash.
        netID (byte-like): The addresses network encoding ID.

    Returns:
        string: Base-58 encoded address.
    """
    b = ByteArray(netID)
    b += k
    b += checksum(b.b)
    return b58encode(b.bytes()).decode()


def decodeAddress(addr: str, netParams: object):
    """
    DecodeAddress decodes the base-58 encoded address and returns the Address if
    it is a valid encoding for a known address type and is for the provided
    network.

    Args:
        addr (str): Base-58 encoded address.
        netParams (module): The network parameters.
    """
    oneIndex = addr.find("1")
    if oneIndex > 1:
        hrp = addr[:oneIndex].lower()
        if hrp == netParams.Bech32HRPSegwit:
            witnessVer, witnessProg = decodeSegWitAddress(netParams.Bech32HRPSegwit, addr)

            # We currently only support P2WPKH and P2WSH, which is
            # witness version 0.
            if witnessVer != 0:
                raise DecredError(f"unsupported witness version {witnessVer}")

            witnessLen = len(witnessProg)
            if witnessLen == 20:
                return AddressWitnessPubKeyHash(witnessProg, netParams)
            elif witnessLen == 32:
                return AddressWitnessScriptHash(witnessProg, netParams)
            else:
                raise DecredError(f"unsupported witness program length {witnessLen}")

    # Serialized public keys are either 65 bytes (130 hex chars) if
    # uncompressed/hybrid or 33 bytes (66 hex chars) if compressed.
    if len(addr) == 130 or len(addr) == 66:
        serializedPubKey = ByteArray(addr)
        return AddressPubKey(serializedPubKey, netParams)

    # Switch on decoded length to determine the type.
    hash160, netID = b58CheckDecode(addr)

    if len(hash160) == RIPEMD160_SIZE:  # P2PKH or P2SH
        isP2PKH = netID == netParams.PubKeyHashAddrID
        isP2SH = netID == netParams.ScriptHashAddrID
        if isP2PKH and isP2SH:
            raise DecredError("address collision")
        elif isP2PKH:
            return AddressPubKeyHash(hash160, netParams)
        elif isP2SH:
            return AddressScriptHash(hash160, netParams)
        else:
            raise DecredError("unknown address type")

    raise DecredError(f"decoded address is of unknown size {len(hash160)}")


def encodeSegWitAddress(hrp: str, witnessVersion: int, witnessProgram: ByteArray) -> str:
    """
    encodeSegWitAddress creates a bech32 encoded address string representation
    from witness version and witness program.
    """
    # # Group the address bytes into 5 bit groups, as this is what is used to
    # # encode each character in the address string.
    # convertedI = bech32.convertbits(witnessProgram.b, 8, 5, True)
    # if not convertedI:
    #     raise DecredError("convertbits error")

    # converted = ByteArray(convertedI)

    # Concatenate the witness version and program, and encode the resulting
    # bytes using bech32 encoding.
    bech = bech32.encode(hrp, witnessVersion, witnessProgram.b)
    if not bech:
        raise DecredError("bech32.encode error")

    # Check validity by decoding the created address.
    version, program = decodeSegWitAddress(hrp, bech)

    if version != witnessVersion or program != witnessProgram:
        raise DecredError("invalid segwit address")

    return bech


def decodeSegWitAddress(hrp: str, addr: str) -> Tuple[int, ByteArray]:
    """
    decodeSegWitAddress parses a bech32 encoded segwit address string and
    returns the witness version and witness program byte representation.
    """
    # Decode the bech32 encoded address.
    ver, dataI = bech32.decode(hrp, addr)
    if not dataI:
        raise DecredError("prefix mismatch")

    return ver, ByteArray(dataI)


# def decodeAddressPubKey(decoded, netParams):
#     """
#     decodeAddressPubKey decodes a pubkey-type address from the serialized
#     pubkey.

#     Args:
#         decoded (bytes): A 33 bytes decoded pubkey such as would be decoded
#             from a base58 string. The first byte indicates the signature suite.
#             For compressed secp256k1 pubkeys, use AddressPubKey directly.
#         netParams (module): The network parameters.
#     """
#     if len(decoded) != 33:
#         raise NotImplementedError(f"unable to decode pubkey of length {len(decoded)}")
#     # First byte is the signature suite and ybit.
#     suite = decoded[0]
#     suite &= 127
#     ybit = not (decoded[0] & (1 << 7) == 0)
#     toAppend = 0x02
#     if ybit:
#         toAppend = 0x03

#     if suite == STEcdsaSecp256k1:
#         b = ByteArray(toAppend) + decoded[1:]
#         return AddressPubKey(b, netParams)
#     elif suite == STEd25519:
#         raise NotImplementedError("Edwards signatures not implemented")
#     elif suite == STSchnorrSecp256k1:
#         raise NotImplementedError("Schnorr signatures not implemented")
#     else:
#         raise NotImplementedError(f"unknown address type {suite}")


# def deriveChildAddress(branchXPub, i, netParams):
#     """
#     The base-58 encoded address for the i'th child.

#     Args:
#         i (int): Child number.
#         netParams (module): Network parameters.

#     Returns:
#         str: Child address, as a base-58 encoded string.
#     """
#     child = branchXPub.child(i)
#     return AddressPubKeyHash(
#         hash160(child.publicKey().serializeCompressed().b), netParams,
#     ).string()


def b58CheckDecode(s: str) -> Tuple[ByteArray, int]:
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
    if len(decoded) < 5:
        raise DecredError("decoded lacking version/checksum")
    version = decoded[0]
    included_cksum = decoded[len(decoded) - 4:]
    computed_cksum = checksum(decoded[: len(decoded) - 4])
    if included_cksum != computed_cksum:
        raise DecredError("checksum error")
    payload = ByteArray(decoded[1: len(decoded) - 4])
    return payload, version


def checksum(b: ByteArray):
    """
    This checksum is used to validate base-58 addresses.

    Args:
        b (byte-like): Bytes to obtain a checksum for.

    Returns:
        bytes: The first 4 bytes of a double sha256 hash of input.
    """
    v = hashlib.sha256(b).digest()
    return hashlib.sha256(v).digest()[:4]


def hash160(b):
    """
    A RIPEMD160 hash of the blake256 hash of the input.

    Args:
        b (byte-like): The bytes to hash.

    Returns:
        ByteArray: A 20-byte hash.
    """
    h = hashlib.new("ripemd160")
    h.update(hashlib.sha256(b).digest())
    return ByteArray(h.digest())


def isEven(i):
    return i % 2 == 0
