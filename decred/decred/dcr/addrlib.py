"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details

Cryptographic functions.
"""


from base58 import b58encode

from decred import DecredError
from decred.crypto.crypto import (
    RIPEMD160_SIZE,
    PKFCompressed,
    PKFUncompressed,
    STEcdsaSecp256k1,
    STEd25519,
    STSchnorrSecp256k1,
    b58CheckDecode,
    checksum,
    hash160,
)
from decred.crypto.secp256k1.curve import curve as Secp256k1
from decred.dcr import nets
from decred.util.encode import BuildyBytes, ByteArray, decodeBlob, unblobCheck


class Address:
    """
    A parent class for all addresses. This class specifies an API that all
    child classes should implement.
    """

    def __init__(self, chainParams):
        """
        Args:
            chainParams (module): The network parameters.
        """
        self.netName = chainParams.Name

    @staticmethod
    def blob(addr):
        """Satisfies the encode.Blobber API"""
        aEnc = addr.string().encode()
        netEnc = addr.netName.encode()
        return BuildyBytes(0).addData(netEnc).addData(aEnc).b

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = decodeBlob(b)
        unblobCheck("Address", ver, len(d), {0: 2})
        return decodeAddress(d[1].decode(), nets.parse(d[0].decode()))

    def __eq__(self, a):
        """Check that other address is equivalent to this address."""
        raise NotImplementedError("__eq__ must be implemented by child class")

    def string(self):
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

    def address(self):
        """
        The string encoding of the payment address associated with the Address
        value

        Returns:
            str: The encoded address.
        """
        raise NotImplementedError("address must be implemented by child class")

    def scriptAddress(self):
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """

        raise NotImplementedError("scriptAddress must be implemented by child class")

    def hash160(self):
        """
        The Hash160(data) where data is the data normally hashed to 160 bits
        from the respective address type.

        Returns:
            ByteArray: The hash.
        """
        raise NotImplementedError("hash160 must be implemented by child class")


class AddressPubKeyHash(Address):
    """
    Address based on a pubkey hash.
    """

    def __init__(self, pkHash=None, netParams=None, sigType=STEcdsaSecp256k1):
        """
        Args:
            pkHash (ByteArray): The hashed pubkey.
            netParams (module): The network parameters.
            sigType (int): The signature type.
        """

        if sigType == STEd25519:  # nocover
            raise NotImplementedError("Edwards not implemented")
        elif sigType == STSchnorrSecp256k1:  # nocover
            raise NotImplementedError("Schnorr not implemented")
        elif sigType != STEcdsaSecp256k1:
            raise NotImplementedError(f"unsupported signature type {sigType}")

        super().__init__(netParams)
        pkh_len = len(pkHash)
        if pkh_len != RIPEMD160_SIZE:
            raise DecredError(
                f"AddressPubKeyHash expected {RIPEMD160_SIZE} bytes, got {pkh_len}"
            )

        self.sigType = sigType
        self.netID = netParams.PubKeyHashAddrID
        self.pkHash = pkHash

    def __eq__(self, a):
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a == self.string()
        elif isinstance(a, AddressPubKeyHash):
            return (
                a.pkHash == self.pkHash
                and a.netID == self.netID
                and a.sigType == self.sigType
            )
        return False

    def string(self):
        """
        A base-58 encoding of the pubkey hash.

        Returns:
            str: The encoded address.
        """
        return encodeAddress(self.pkHash, self.netID)

    def address(self):
        """
        The string encoding of a pay-to-pubkey-hash address.

        Returns:
            str: The encoded address.
        """
        return self.string()

    def scriptAddress(self):
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.pkHash.copy()

    def hash160(self):
        """
        For AddressPubKeyHash, hash160 is the same as scriptAddress.

        Returns:
            ByteArray: The hash.
        """
        return self.pkHash.copy()


class AddressSecpPubKey(Address):
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
        fmt = serializedPubkey[0]
        if fmt in (0x02, 0x03):
            pkFormat = PKFCompressed
        elif fmt == 0x04:
            pkFormat = PKFUncompressed
        else:
            raise NotImplementedError(f"unknown pubkey format {fmt}")
        self.pubkeyFormat = pkFormat
        self.netID = self.pubkeyID = netParams.PubKeyAddrID
        self.pubkeyHashID = netParams.PubKeyHashAddrID
        self.pubkey = pubkey

    def __eq__(self, a):
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a == self.address() or a == self.string()
        elif isinstance(a, AddressSecpPubKey):
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
        raise NotImplementedError(f"unknown pubkey format {fmt}")

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
            buf[0] |= 1 << 7
        buf += compressed[1:]
        encoded += buf
        encoded += checksum(encoded.b)
        return b58encode(encoded.bytes()).decode()

    def address(self):
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
        return encodeAddress(hash160(self.serialize().bytes()), self.pubkeyHashID)

    def scriptAddress(self):
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.serialize()

    def hash160(self):
        """
        The hash160 of the serialized pubkey.

        Returns:
            ByteArray: The hash.
        """
        return hash160(self.serialize().bytes())


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

    def __eq__(self, a):
        """Check that other address is equivalent to this address."""
        if isinstance(a, str):
            return a == self.string()
        elif isinstance(a, AddressScriptHash):
            return a.scriptHash == self.scriptHash and a.netID == self.netID
        return False

    def string(self):
        """
        A base-58 encoding of the pubkey hash.

        Returns:
            str: The encoded address.
        """
        return encodeAddress(self.scriptHash, self.netID)

    def address(self):
        """
        The string encoding of a pay-to-script-hash address.

        Returns:
            str: The encoded address.
        """
        return self.string()

    def scriptAddress(self):
        """
        The raw bytes of the address to be used when inserting the address into
        a txout's script.

        Returns:
            ByteArray: The script address.
        """
        return self.scriptHash.copy()

    def hash160(self):
        """
        A copy of the scriptHash.

        Returns:
            ByteArray: The hash.
        """
        return self.scriptHash.copy()


class AddressEdwardsPubKey(Address):
    """unimplemented"""

    def __init__(*a, **k):
        raise NotImplementedError("AddressEdwardsPubKey not implemented")


class AddressSecSchnorrPubKey(Address):
    """unimplemented"""

    def __init__(*a, **k):
        raise NotImplementedError("AddressSecSchnorrPubKey implemented")


def encodeAddress(k, netID):
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


def decodeAddress(addr, netParams):
    """
    DecodeAddress decodes the base-58 encoded address and returns the Address if
    it is a valid encoding for a known address type and is for the provided
    network.

    Args:
        addr (str): Base-58 encoded address.
        netParams (module): The network parameters.
    """
    # Switch on decoded length to determine the type.
    decoded, netID = b58CheckDecode(addr)
    if netID == netParams.PubKeyAddrID:
        return decodeAddressPubKey(decoded, netParams)
    elif netID == netParams.PubKeyHashAddrID:
        return AddressPubKeyHash(decoded, netParams, STEcdsaSecp256k1)
    elif netID == netParams.PKHEdwardsAddrID:
        raise NotImplementedError("Edwards signatures not implemented")
    elif netID == netParams.PKHSchnorrAddrID:
        raise NotImplementedError("Schnorr signatures not implemented")
    elif netID == netParams.ScriptHashAddrID:
        return AddressScriptHash(decoded, netParams)
    raise NotImplementedError(f"unknown network ID {netID}")


def decodeAddressPubKey(decoded, netParams):
    """
    decodeAddressPubKey decodes a pubkey-type address from the serialized
    pubkey.

    Args:
        decoded (bytes): A 33 bytes decoded pubkey such as would be decoded
            from a base58 string. The first byte indicates the signature suite.
            For compressed secp256k1 pubkeys, use AddressSecpPubKey directly.
        netParams (module): The network parameters.
    """
    if len(decoded) != 33:
        raise NotImplementedError(f"unable to decode pubkey of length {len(decoded)}")
    # First byte is the signature suite and ybit.
    suite = decoded[0]
    suite &= 127
    ybit = not (decoded[0] & (1 << 7) == 0)
    toAppend = 0x02
    if ybit:
        toAppend = 0x03

    if suite == STEcdsaSecp256k1:
        b = ByteArray(toAppend) + decoded[1:]
        return AddressSecpPubKey(b, netParams)
    elif suite == STEd25519:
        raise NotImplementedError("Edwards signatures not implemented")
    elif suite == STSchnorrSecp256k1:
        raise NotImplementedError("Schnorr signatures not implemented")
    else:
        raise NotImplementedError(f"unknown address type {suite}")


def deriveChildAddress(branchXPub, i, netParams):
    """
    The base-58 encoded address for the i'th child.

    Args:
        i (int): Child number.
        netParams (module): Network parameters.

    Returns:
        str: Child address, as a base-58 encoded string.
    """
    child = branchXPub.child(i)
    return AddressPubKeyHash(
        hash160(child.publicKey().serializeCompressed().b), netParams, STEcdsaSecp256k1,
    ).string()
