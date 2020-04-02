"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details

Based on dcrd txscript.
"""

import bisect
import math

from decred import DecredError
from decred.crypto import crypto, opcode
from decred.crypto.secp256k1.curve import curve as Curve
from decred.dcr import addrlib
from decred.util import helpers
from decred.util.encode import ByteArray

from .wire import msgtx, wire


log = helpers.getLogger("TXSCRIPT")

HASH_SIZE = 32
SHA256_SIZE = 32
BLAKE256_SIZE = 32
MAX_UINT64 = 18446744073709551615

NonStandardTy = 0  # None of the recognized forms.
PubKeyTy = 1  # Pay pubkey.
PubKeyHashTy = 2  # Pay pubkey hash.
ScriptHashTy = 3  # Pay to script hash.
MultiSigTy = 4  # Multi signature.
NullDataTy = 5  # Empty data-only (provably prunable).
StakeSubmissionTy = 6  # Stake submission.
StakeGenTy = 7  # Stake generation
StakeRevocationTy = 8  # Stake revocation.
StakeSubChangeTy = 9  # Change for stake submission tx.
PubkeyAltTy = 10  # Alternative signature pubkey.
PubkeyHashAltTy = 11  # Alternative signature pubkey hash.

# DefaultScriptVersion is the default scripting language version
# representing extended Decred script.
DefaultScriptVersion = 0

consensusVersion = 0

# MaxInputsPerSStx is the maximum number of inputs allowed in an SStx.
MaxInputsPerSStx = 64

# MaxOutputsPerSStx is the maximum number of outputs allowed in an SStx;
# you need +1 for the tagged SStx output.
MaxOutputsPerSStx = MaxInputsPerSStx * 2 + 1

# NumInputsPerSSGen is the exact number of inputs for an SSGen
# (stakebase) tx.  Inputs are a tagged SStx output and a stakebase (null)
# input.
NumInputsPerSSGen = 2  # SStx and stakebase

# MaxOutputsPerSSGen is the maximum number of outputs in an SSGen tx,
# which are all outputs to the addresses specified in the OP_RETURNs of
# the original SStx referenced as input plus reference and vote
# OP_RETURN outputs in the zeroeth and first position.
MaxOutputsPerSSGen = MaxInputsPerSStx + 2

# NumInputsPerSSRtx is the exact number of inputs for an SSRtx (stake
# revocation tx); the only input should be the SStx output.
NumInputsPerSSRtx = 1

# MaxOutputsPerSSRtx is the maximum number of outputs in an SSRtx, which
# are all outputs to the addresses specified in the OP_RETURNs of the
# original SStx referenced as input plus a reference to the block header
# hash of the block in which voting was missed.
MaxOutputsPerSSRtx = MaxInputsPerSStx

# SStxPKHMinOutSize is the minimum size of an OP_RETURN commitment output
# for an SStx tx.
# 20 bytes P2SH/P2PKH + 8 byte amount + 4 byte fee range limits
SStxPKHMinOutSize = 32

# SStxPKHMaxOutSize is the maximum size of an OP_RETURN commitment output
# for an SStx tx.
SStxPKHMaxOutSize = 77

# SSGenBlockReferenceOutSize is the size of a block reference OP_RETURN
# output for an SSGen tx.
SSGenBlockReferenceOutSize = 38

# SSGenVoteBitsOutputMinSize is the minimum size for a VoteBits push
# in an SSGen.
SSGenVoteBitsOutputMinSize = 4

# SSGenVoteBitsOutputMaxSize is the maximum size for a VoteBits push
# in an SSGen.
SSGenVoteBitsOutputMaxSize = 77

# Hash type bits from the end of a signature.
SigHashAll = 0x1
SigHashNone = 0x2
SigHashSingle = 0x3
SigHashAnyOneCanPay = 0x80

# sigHashMask defines the number of bits of the hash type which is used
# to identify which outputs are signed.
sigHashMask = 0x1F

# SigHashSerializePrefix indicates the serialization does not include
# any witness data.
SigHashSerializePrefix = 1

# SigHashSerializeWitness indicates the serialization only contains
# witness data.
SigHashSerializeWitness = 3

# from chaincfg
SigHashOptimization = False

varIntSerializeSize = wire.varIntSerializeSize

# These are the constants specified for maximums in individual scripts.
MaxOpsPerScript = 255  # Max number of non-push operations.
MaxPubKeysPerMultiSig = 20  # Multisig can't have more sigs than this.
MaxScriptElementSize = 2048  # Max bytes pushable to the stack.

# P2PKHPkScriptSize is the size of a transaction output script that
# pays to a compressed pubkey hash.  It is calculated as:
#
#   - OP_DUP
#   - OP_HASH160
#   - OP_DATA_20
#   - 20 bytes pubkey hash
#   - OP_EQUALVERIFY
#   - OP_CHECKSIG
P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1

# RedeemP2PKSigScriptSize is the worst case (largest) serialize size
# of a transaction input script that redeems a compressed P2PK output.
# It is calculated as:
#
#   - OP_DATA_73
#   - 72 bytes DER signature + 1 byte sighash
RedeemP2PKSigScriptSize = 1 + 73

# P2SHPkScriptSize is the size of a transaction output script that
# pays to a script hash.  It is calculated as:
#
#   - OP_HASH160
#   - OP_DATA_20
#   - 20 bytes script hash
#   - OP_EQUAL
P2SHPkScriptSize = 1 + 1 + 20 + 1

# Many of these constants were pulled from the dcrd, and are left as mixed case
# to maintain reference.

# DefaultRelayFeePerKb is the default minimum relay fee policy for a mempool.
DefaultRelayFeePerKb = 1e4

# MaxStandardTxSize is the maximum size allowed for transactions that are
# considered standard and will therefore be relayed and considered for mining.
MaxStandardTxSize = 1e5

# AtomsPerCent is the number of atomic units in one coin cent.
AtomsPerCent = 1e6

# AtomsPerCoin is the number of atomic units in one coin.
AtomsPerCoin = 1e8

# MaxAmount is the maximum transaction amount allowed in atoms.
# Decred - Changeme for release
MaxAmount = 21e6 * AtomsPerCoin

opNonstake = opcode.OP_NOP10

# RedeemP2PKHSigScriptSize is the worst case (largest) serialize size
# of a transaction input script that redeems a compressed P2PKH output.
# It is calculated as:
#
#   - OP_DATA_73
#   - 72 bytes DER signature + 1 byte sighash
#   - OP_DATA_33
#   - 33 bytes serialized compressed pubkey
RedeemP2PKHSigScriptSize = 1 + 73 + 1 + 33

# RedeemP2SHSigScriptSize is the worst case (largest) serialize size
# of a transaction input script that redeems a P2SH output.
# It is calculated as:
#
#  - OP_DATA_73
#  - 73-byte signature
#  - OP_DATA_35
#  - OP_DATA_33
#  - 33 bytes serialized compressed pubkey
#  - OP_CHECKSIG
RedeemP2SHSigScriptSize = 1 + 73 + 1 + 1 + 33 + 1

# TicketCommitmentScriptSize is the size of a ticket purchase commitment
# script. It is calculated as:
#
#   - OP_RETURN
#   - OP_DATA_30
#   - 20 bytes P2SH/P2PKH
#   - 8 byte amount
#   - 2 byte fee range limits
TicketCommitmentScriptSize = 1 + 1 + 20 + 8 + 2

# generatedTxVersion is the version of the transaction being generated.
# It is defined as a constant here rather than using the wire.TxVersion
# constant since a change in the transaction version will potentially
# require changes to the generated transaction.  Thus, using the wire
# constant for the generated transaction version could allow creation
# of invalid transactions for the updated version.
generatedTxVersion = 1

# MaxStackSize is the maximum combined height of stack and alt stack
# during execution.
MaxStackSize = 1024

# MaxScriptSize is the maximum allowed length of a raw script.
MaxScriptSize = 16384

# MaxDataCarrierSize is the maximum number of bytes allowed in pushed
# data to be considered a nulldata transaction.
MaxDataCarrierSize = 256

# consensusVersion = txscript.consensusVersion
consensusVersion = 0

# MaxInputsPerSStx is the maximum number of inputs allowed in an SStx.
MaxInputsPerSStx = 64

# MaxOutputsPerSStx is the maximum number of outputs allowed in an SStx;
# you need +1 for the tagged SStx output.
MaxOutputsPerSStx = MaxInputsPerSStx * 2 + 1

# validSSGenReferenceOutPrefix is the valid prefix for a block
# reference output for an SSGen tx.
validSSGenReferenceOutPrefix = ByteArray([opcode.OP_RETURN, opcode.OP_DATA_36])

# validSSGenVoteOutMinPrefix is the valid prefix for a vote output for an
# SSGen tx.
validSSGenVoteOutMinPrefix = ByteArray([opcode.OP_RETURN, opcode.OP_DATA_2])

# MaxSingleBytePushLength is the largest maximum push for an
# SStx commitment or VoteBits push.
MaxSingleBytePushLength = 75

# SStxPKHMinOutSize is the minimum size of an OP_RETURN commitment output
# for an SStx tx.
# 20 bytes P2SH/P2PKH + 8 byte amount + 4 byte fee range limits
SStxPKHMinOutSize = 32

# SStxPKHMaxOutSize is the maximum size of an OP_RETURN commitment output
# for an SStx tx.
SStxPKHMaxOutSize = 77

# defaultTicketFeeLimits is the default byte string for the default
# fee limits imposed on a ticket.
defaultTicketFeeLimits = 0x5800

# SStxVoteReturnFractionMask extracts the return fraction from a
# commitment output version.
# If after applying this mask &0x003f is given, the entire amount of
# the output is allowed to be spent as fees if the flag to allow fees
# is set.
SStxVoteReturnFractionMask = 0x003F

# SStxRevReturnFractionMask extracts the return fraction from a
# commitment output version.
# If after applying this mask &0x3f00 is given, the entire amount of
# the output is allowed to be spent as fees if the flag to allow fees
# is set.
SStxRevReturnFractionMask = 0x3F00


# SStxVoteFractionFlag is a bitflag mask specifying whether or not to
# apply a fractional limit to the amount used for fees in a vote.
# 00000000 00000000 = No fees allowed
# 00000000 01000000 = Apply fees rule
SStxVoteFractionFlag = 0x0040

# SStxRevFractionFlag is a bitflag mask specifying whether or not to
# apply a fractional limit to the amount used for fees in a vote.
# 00000000 00000000 = No fees allowed
# 01000000 00000000 = Apply fees rule
SStxRevFractionFlag = 0x4000

# A couple of hashing functions from the crypto module.
mac = crypto.mac
hashH = crypto.hashH


def scriptTree(scriptClass):
    """
    Returns wire.TxTreeStake for stake related scripts, else wire.TxTreeRegular.

    Args:
        scriptClass(int): The script's class.

    Returns:
        int: The script's tree.
    """
    if scriptClass < 0 or scriptClass > 11:
        raise DecredError("unknown script class: {}".format(scriptClass))

    return (
        wire.TxTreeStake
        if scriptClass
        in (StakeSubmissionTy, StakeSubChangeTy, StakeGenTy, StakeRevocationTy)
        else wire.TxTreeRegular
    )


def canonicalPadding(b):
    """
    canonicalPadding checks whether a big-endian encoded integer could
    possibly be misinterpreted as a negative number (even though OpenSSL
    treats all numbers as unsigned), or if there is any unnecessary
    leading zero padding.
    """
    if b[0] & 0x80 == 0x80:
        raise DecredError("negative number")
    if len(b) > 1 and b[0] == 0x00 and b[1] & 0x80 != 0x80:
        raise DecredError("excessive padding")


class Signature:
    """
    The Signature class represents an ECDSA-algorithm signature.
    """

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def serialize(self):
        """
        serialize returns the ECDSA signature in the more strict DER format.  Note
        that the serialized bytes returned do not include the appended hash type
        used in Decred signature scripts.

        encoding/asn1 is broken so we hand roll this output:
        0x30 <length> 0x02 <length r> r 0x02 <length s> s
        """
        # Curve order and halforder, used to tame ECDSA malleability (see BIP-0062)
        order = Curve.N
        halforder = order >> 1
        # low 'S' malleability breaker
        sigS = self.s
        if sigS > halforder:
            sigS = order - sigS
        # Ensure the encoded bytes for the r and s values are canonical and
        # thus suitable for DER encoding.
        rb = canonicalizeInt(self.r)
        sb = canonicalizeInt(sigS)

        # total length of returned signature is 1 byte for each magic and
        # length (6 total), plus lengths of r and s
        length = 6 + len(rb) + len(sb)
        b = ByteArray(0, length=length)

        b[0] = 0x30
        b[1] = ByteArray(length - 2, length=1)
        b[2] = 0x02
        b[3] = ByteArray(len(rb), length=1)
        offset = 4
        b[offset] = rb
        offset += len(rb)
        b[offset] = 0x02
        offset += 1
        b[offset] = ByteArray(len(sb), length=1)
        offset += 1
        b[offset] = sb
        return b

    @staticmethod
    def parse(sigBytes, der):
        """
        Parse sigBytes to make sure they make up a valid Signature.

        Args:
            sigBytes (byte-like): The bytes of the signature.
            der (bool): Whether to check for padding and sign.
        Returns:
            object: the ECDSA Signature.
        """
        # minimal message is when both numbers are 1 bytes. adding up to:
        # 0x30 + len + 0x02 + 0x01 + <byte> + 0x2 + 0x01 + <byte>
        if len(sigBytes) < 8:
            raise DecredError("malformed signature: too short")

        # 0x30
        index = 0
        if sigBytes[index] != 0x30:
            raise DecredError("malformed signature: no header magic")
        index += 1
        # length of remaining message
        siglen = sigBytes[index]
        index += 1
        if siglen + 2 > len(sigBytes):
            raise DecredError("malformed signature: bad length")
        # trim the slice we're working on so we only look at what matters.
        sigBytes = sigBytes[: siglen + 2]

        # 0x02
        if sigBytes[index] != 0x02:
            raise DecredError("malformed signature: no 1st int marker")
        index += 1

        # Length of signature r.
        rLen = sigBytes[index]
        # must be positive, must be able to fit in another 0x2, <len> <s>
        # hence the -3. We assume that the length must be at least one byte.
        index += 1
        if rLen <= 0 or rLen > len(sigBytes) - index - 3:
            raise DecredError("malformed signature: bogus r length")

        # Then r itself.
        rBytes = sigBytes[index : index + rLen]
        if der:
            try:
                canonicalPadding(rBytes)
            except Exception as e:
                raise DecredError(
                    "malformed signature: bogus r padding or sign: {}".format(e)
                )

        index += rLen
        # 0x02. length already checked in previous if.
        if sigBytes[index] != 0x02:
            raise DecredError("malformed signature: no 2nd int marker")
        index += 1

        # Length of signature s.
        sLen = sigBytes[index]
        index += 1
        # s should be the rest of the bytes.
        if sLen <= 0 or sLen > len(sigBytes) - index:
            raise DecredError("malformed signature: bogus S length")

        # Then s itself.
        sBytes = sigBytes[index : index + sLen]
        if der:
            try:
                canonicalPadding(rBytes)
            except Exception as e:
                raise DecredError(
                    "malformed signature: bogus s padding or sign: {}".format(e)
                )

        index += sLen
        # sanity check length parsing
        if index != len(sigBytes):
            raise DecredError(
                f"malformed signature: bad final length {index} != {len(sigBytes)}"
            )

        signature = Signature(rBytes, sBytes)

        # FWIW the ecdsa spec states that r and s must be | 1, N - 1 |
        if signature.r.int() < 1:
            raise DecredError("signature r is less than one")
        if signature.s.int() < 1:
            raise DecredError("signature s is less than one")
        if signature.r.int() >= Curve.N:
            raise DecredError("signature r is >= curve.N")
        if signature.s.int() >= Curve.N:
            raise DecredError("signature s is >= curve.N")

        return signature


class ScriptTokenizer:
    """
    ScriptTokenizer provides a facility for easily and efficiently tokenizing
    transaction scripts without creating allocations.  Each successive opcode is
    parsed with the Next function, which returns false when iteration is
    complete, either due to successfully tokenizing the entire script or
    encountering a parse error.  In the case of failure, the Err function may be
    used to obtain the specific parse error.

    Upon successfully parsing an opcode, the opcode and data associated with it
    may be obtained via the Opcode and Data functions, respectively.
    """

    def __init__(self, version, script):
        self.script = script
        self.version = version
        self.offset = 0
        self.op = None
        self.d = ByteArray(b"")
        self.err = None

    def next(self):
        """
        next attempts to parse the next opcode and returns whether or not it was
        successful.  It will not be successful if invoked when already at the end of
        the script, a parse failure is encountered, or an associated error already
        exists due to a previous parse failure.

        In the case of a true return, the parsed opcode and data can be obtained with
        the associated functions and the offset into the script will either point to
        the next opcode or the end of the script if the final opcode was parsed.

        In the case of a false return, the parsed opcode and data will be the last
        successfully parsed values (if any) and the offset into the script will
        either point to the failing opcode or the end of the script if the function
        was invoked when already at the end of the script.

        Invoking this function when already at the end of the script is not
        considered an error and will simply return false.
        """
        if self.done():
            return False
        opcodeArrayRef = opcode.opcodeArray

        op = opcodeArrayRef[self.script[self.offset]]
        if op.length == 1:
            # No additional data.  Note that some of the opcodes, notably OP_1NEGATE,
            # OP_0, and OP_[1-16] represent the data themselves.
            self.offset += 1
            self.op = op
            self.d = ByteArray(b"")
            return True
        elif op.length > 1:
            # Data pushes of specific lengths -- OP_DATA_[1-75].
            script = self.script[self.offset :]
            if len(script) < op.length:
                self.err = DecredError(
                    "opcode %s requires %d bytes, but script only has %d remaining"
                    % (op.name, op.length, len(script))
                )
                return False

            # Move the offset forward and set the opcode and data accordingly.
            self.offset += op.length
            self.op = op
            self.d = script[1 : op.length]
            return True
        elif op.length < 0:
            # Data pushes with parsed lengths -- OP_PUSHDATA{1,2,4}.
            script = self.script[self.offset + 1 :]
            if len(script) < -op.length:
                self.err = DecredError(
                    "opcode %s requires %d bytes, but script only has %d remaining"
                    % (op.name, -op.length, len(script))
                )
                return False

            # Next -length bytes are little endian length of data.
            if op.length == -1:
                dataLen = script[0]
            elif op.length == -2:
                dataLen = script[:2].unLittle().int()
            elif op.length == -4:
                dataLen = script[:4].unLittle().int()
            else:
                self.err = DecredError("invalid opcode length %d" % op.length)
                return False

            # Move to the beginning of the data.
            script = script[-op.length :]

            # Disallow entries that do not fit script or were sign extended.
            if dataLen > len(script) or dataLen < 0:
                self.err = DecredError(
                    "opcode %s pushes %d bytes, but script only has %d remaining"
                    % (op.name, dataLen, len(script))
                )
                return False

            # Move the offset forward and set the opcode and data accordingly.
            self.offset += 1 - op.length + dataLen
            self.op = op
            self.d = script[:dataLen]
            return True

        # The only remaining case is an opcode with length zero which is
        # impossible.
        raise AssertionError("unreachable")

    def done(self):
        """
        Script parsing has completed

        Returns:
            bool: True if script parsing complete.
        """
        return self.err is not None or self.offset >= len(self.script)

    def opcode(self):
        """
        The current step's opcode

        Returns:
            int: the opcode. See crypto.opcode for more information.
        """
        if self.op is None:
            return None
        return self.op.value

    def data(self):
        """
        Data returns the data associated with the most recently successfully parsed
        opcode.

        Returns:
            ByteArray: The data
        """
        return self.d

    def byteIndex(self):
        """
        ByteIndex returns the current offset into the full script that will be
        parsed next and therefore also implies everything before it has already
        been parsed.

        Returns:
            int: the current offset
        """
        return self.offset


class Credit:
    """
    Credit is the type representing a transaction output which was spent or
    is still spendable by wallet.  A UTXO is an unspent Credit, but not all
    Credits are UTXOs.
    """

    def __init__(
        self,
        op,
        blockMeta,
        amount,
        pkScript,
        received,
        fromCoinBase=False,
        hasExpiry=False,
    ):
        self.op = op
        self.blockMeta = blockMeta
        self.amount = amount
        self.pkScript = pkScript
        self.received = received
        self.fromCoinBase = fromCoinBase
        self.hasExpiry = hasExpiry


class ExtendedOutPoint:
    def __init__(self, op, amt, pkScript):
        self.op = op
        self.amt = amt
        self.pkScript = pkScript


def checkScriptParses(scriptVersion, script):
    """
    checkScriptParses returns None when the script parses without error.

    Args:
        scriptVersion (int): The script version.
        script (ByteArray): The script.

    Returns:
        None or Exception: None on success. Exception is returned, not raised.
    """
    tokenizer = ScriptTokenizer(scriptVersion, script)
    while tokenizer.next():
        pass
    return tokenizer.err


def finalOpcodeData(scriptVersion, script):
    """
    finalOpcodeData returns the data associated with the final opcode in the
    script.  It will return nil if the script fails to parse.

    Args:
        scriptVersion (int): The script version.
        script (ByteArray): The script.

    Returns:
        ByteArray: The data associated with the final script opcode.
    """
    # Avoid unnecessary work.
    if len(script) == 0:
        return None

    data = None
    tokenizer = ScriptTokenizer(scriptVersion, script)
    while tokenizer.next():
        data = tokenizer.data()
    if tokenizer.err is not None:
        return None
    return data


def canonicalizeInt(val):
    """
    canonicalizeInt returns the bytes for the passed big integer adjusted as
    necessary to ensure that a big-endian encoded integer can't possibly be
    misinterpreted as a negative number.  This can happen when the most
    significant bit is set, so it is padded by a leading zero byte in this case.
    Also, the returned bytes will have at least a single byte when the passed
    value is 0.  This is required for DER encoding.

    Args:
        val (int): The value to encode.

    Returns:
        ByteArray: The encoded integer with any necessary zero padding.
    """
    b = ByteArray(val)
    if len(b) == 0:
        b = ByteArray(0, length=1)
    if (b[0] & 0x80) != 0:
        b = ByteArray(0, length=len(b) + 1) | b
    return b


def scriptNumBytes(n):
    """
    scriptNumBytes returns a minimal encoding for a signed integer as bytes.
    Based on dcrd/txscript (scriptNum).Bytes.

    Args:
        n (int): The integer to encode.

    Returns:
        ByteArray: The encoded bytes.
    """
    if n == 0:
        return ByteArray()

    isNegative = n < 0
    if isNegative:
        n = -n

    result = ByteArray(length=9)
    i = 0
    while n > 0:
        result[i] = n & 0xFF
        n = n >> 8
        i += 1

    if result[i - 1] & 0x80 != 0:
        extraByte = 0x00
        if isNegative:
            extraByte = 0x80
        result[i] = extraByte
        i += 1
    elif isNegative:
        result[i - 1] |= 0x80

    return result[:i]


def hashToInt(h):
    """
    hashToInt converts a hash value to an integer. There is some disagreement
    about how this is done. [NSA] suggests that this is done in the obvious
    manner, but [SECG] truncates the hash to the bit-length of the curve order
    first. We follow [SECG] because that's what OpenSSL does. Additionally,
    OpenSSL right shifts excess bits from the number if the hash is too large
    and we mirror that too.
    This is borrowed from crypto/ecdsa.

    Args:
        h (byte-like): The hash to convert.

    Returns:
        int: The integer.
    """
    orderBits = Curve.N.bit_length()
    orderBytes = (orderBits + 7) // 8
    if len(h) > orderBytes:
        h = h[:orderBytes]

    ret = int.from_bytes(h, byteorder="big")
    excess = len(h) * 8 - orderBits
    if excess > 0:
        ret = ret >> excess
    return ret


def getScriptClass(scriptVersion, script):
    """
    getScriptClass returns the class of the script from the known standard
    types. NonStandardTy will be returned when the script does not parse.

    NOTE:  All scripts that are not version 0 are currently considered
    non standard.
    """
    if scriptVersion != DefaultScriptVersion:
        return NonStandardTy
    elif isPubKeyScript(script):
        return PubKeyTy
    elif isPubKeyAltScript(script):
        return PubkeyAltTy
    elif isPubKeyHashScript(script):
        return PubKeyHashTy
    elif isPubKeyHashAltScript(script):
        return PubkeyHashAltTy
    elif isScriptHashScript(script):
        return ScriptHashTy
    elif isMultisigScript(scriptVersion, script):
        return MultiSigTy
    elif isNullDataScript(scriptVersion, script):
        return NullDataTy
    elif isStakeSubmissionScript(scriptVersion, script):
        return StakeSubmissionTy
    elif isStakeGenScript(scriptVersion, script):
        return StakeGenTy
    elif isStakeRevocationScript(scriptVersion, script):
        return StakeRevocationTy
    elif isStakeChangeScript(scriptVersion, script):
        return StakeSubChangeTy
    return NonStandardTy


def isPubKeyAltScript(script):
    """
    isPubKeyAltScript returns whether or not the passed script is a standard
    pay-to-alt-pubkey script.
    """
    pk, _ = extractPubKeyAltDetails(script)
    return pk is not None


def extractPubKeyAltDetails(script):
    """
    extractPubKeyAltDetails extracts the public key and signature type from the
    passed script if it is a standard pay-to-alt-pubkey script.  It will return
    None otherwise.

    Args:
        script (bytes-like): The script to extract from.

    Returns:
        (bytes-like): The pubkey or None.
        (int): The signature type or 0.
    """
    # A pay-to-alt-pubkey script is of the form:
    #  PUBKEY SIGTYPE OP_CHECKSIGALT
    #
    # The only two currently supported alternative signature types are ed25519
    # and schnorr + secp256k1 (with a compressed pubkey).
    #
    #  OP_DATA_32 <32-byte pubkey> <1-byte ed25519 sigtype> OP_CHECKSIGALT
    #  OP_DATA_33 <33-byte pubkey> <1-byte schnorr+secp sigtype> OP_CHECKSIGALT

    # The script can't possibly be a pay-to-alt-pubkey script if it doesn't
    # end with OP_CHECKSIGALT or have at least two small integer pushes
    # preceding it (although any reasonable pubkey will certainly be larger).
    # Fail fast to avoid more work below.
    if len(script) < 3 or script[-1] != opcode.OP_CHECKSIGALT:
        return None, 0

    if (
        len(script) == 35
        and script[0] == opcode.OP_DATA_32
        and isSmallInt(script[33])
        and asSmallInt(script[33]) == crypto.STEd25519
    ):
        return script[1:33], crypto.STEd25519

    if (
        len(script) == 36
        and script[0] == opcode.OP_DATA_33
        and isSmallInt(script[34])
        and asSmallInt(script[34]) == crypto.STSchnorrSecp256k1
        and isStrictPubKeyEncoding(script[1:34])
    ):
        return script[1:34], crypto.STSchnorrSecp256k1

    return None, 0


def isPubKeyHashAltScript(script):
    """
    isPubKeyHashAltScript returns whether or not the passed script is a standard
    pay-to-alt-pubkey-hash script.
    """
    pk, _ = extractPubKeyHashAltDetails(script)
    return pk is not None


def isStandardAltSignatureType(op):
    """
    isStandardAltSignatureType returns whether or not the provided opcode
    represents a push of a standard alt signature type.
    """
    if not isSmallInt(op):
        return False

    sigType = asSmallInt(op)
    return sigType in (crypto.STEd25519, crypto.STSchnorrSecp256k1)


def extractPubKeyHashAltDetails(script):
    """
    extractPubKeyHashAltDetails extracts the public key hash and signature type
    from the passed script if it is a standard pay-to-alt-pubkey-hash script.  It
    will return None otherwise.

    Args:
        script (bytes-like): The script to extract from.

    Returns:
        (bytes-like): The pubkey hash or None.
        (int): The signature type or 0.
    """
    # A pay-to-alt-pubkey-hash script is of the form:
    #  DUP HASH160 <20-byte hash> EQUALVERIFY SIGTYPE CHECKSIG
    #
    # The only two currently supported alternative signature types are ed25519
    # and schnorr + secp256k1 (with a compressed pubkey).
    #
    #  DUP HASH160 <20-byte hash> EQUALVERIFY <1-byte ed25519 sigtype> CHECKSIG
    #  DUP HASH160 <20-byte hash> EQUALVERIFY <1-byte schnorr+secp sigtype> CHECKSIG
    #
    #  Notice that OP_0 is not specified since signature type 0 disabled.
    if (
        len(script) == 26
        and script[0] == opcode.OP_DUP
        and script[1] == opcode.OP_HASH160
        and script[2] == opcode.OP_DATA_20
        and script[23] == opcode.OP_EQUALVERIFY
        and isStandardAltSignatureType(script[24])
        and script[25] == opcode.OP_CHECKSIGALT
    ):
        return script[3:23], asSmallInt(script[24])

    return None, 0


def isPubKeyHashScript(script):
    return not extractPubKeyHash(script) is None


def extractPubKeyHash(script):
    """
    extractPubKeyHash extracts the public key hash from the passed script if it
    is a standard pay-to-pubkey-hash script. It will return None otherwise.
    """
    # A pay-to-pubkey-hash script is of the form:
    # OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    if (
        len(script) == 25
        and script[0] == opcode.OP_DUP
        and script[1] == opcode.OP_HASH160
        and script[2] == opcode.OP_DATA_20
        and script[23] == opcode.OP_EQUALVERIFY
        and script[24] == opcode.OP_CHECKSIG
    ):

        return script[3:23]
    return None


def extractScriptHash(pkScript):
    """
    extractScriptHash extracts the script hash from the passed script if it is a
    standard pay-to-script-hash script.  It will return nil otherwise.

    NOTE: This function is only valid for version 0 opcodes.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    # A pay-to-script-hash script is of the form:
    #  OP_HASH160 <20-byte scripthash> OP_EQUAL
    if (
        len(pkScript) == 23
        and pkScript[0] == opcode.OP_HASH160
        and pkScript[1] == opcode.OP_DATA_20
        and pkScript[22] == opcode.OP_EQUAL
    ):

        return pkScript[2:22]
    return None


def isScriptHashScript(pkScript):
    """
    isScriptHashScript returns whether or not the passed script is a standard
    pay-to-script-hash script.
    """
    return extractScriptHash(pkScript) is not None


def extractPubKey(script):
    """
    extractPubKey extracts either compressed or uncompressed public key from the
    passed script if it is a either a standard pay-to-compressed-secp256k1-pubkey
    or pay-to-uncompressed-secp256k1-pubkey script, respectively.  It will return
    nil otherwise.
    """
    pubkey = extractCompressedPubKey(script)
    if pubkey:
        return pubkey
    return extractUncompressedPubKey(script)


def extractCompressedPubKey(script):
    """
    extractCompressedPubKey extracts a compressed public key from the passed
    script if it is a standard pay-to-compressed-secp256k1-pubkey script.  It
    will return nil otherwise.
    """
    # pay-to-compressed-pubkey script is of the form:
    #  OP_DATA_33 <33-byte compresed pubkey> OP_CHECKSIG

    # All compressed secp256k1 public keys must start with 0x02 or 0x03.
    if (
        len(script) == 35
        and script[34] == opcode.OP_CHECKSIG
        and script[0] == opcode.OP_DATA_33
        and (script[1] == 0x02 or script[1] == 0x03)
    ):
        return script[1:34]
    return None


def extractUncompressedPubKey(script):
    """
    extractUncompressedPubKey extracts an uncompressed public key from the
    passed script if it is a standard pay-to-uncompressed-secp256k1-pubkey
    script.  It will return nil otherwise.
    """
    # A pay-to-compressed-pubkey script is of the form:
    #  OP_DATA_65 <65-byte uncompressed pubkey> OP_CHECKSIG

    # All non-hybrid uncompressed secp256k1 public keys must start with 0x04.
    if (
        len(script) == 67
        and script[66] == opcode.OP_CHECKSIG
        and script[0] == opcode.OP_DATA_65
        and script[1] == 0x04
    ):

        return script[1:66]
    return None


def isPubKeyScript(script):
    """
    isPubKeyScript returns whether or not the passed script is either a standard
    pay-to-compressed-secp256k1-pubkey or pay-to-uncompressed-secp256k1-pubkey
    script.
    """
    return extractPubKey(script) is not None


def isStakeScriptHash(script, stakeOpcode):
    """
    isStakeScriptHash returns whether or not the passed public key script is a
    standard pay-to-script-hash script tagged with the provided stake opcode.

    Args:
        script (ByteArray): The script to check.
        stakeOpcode (int): An opcode for the type of stake transaction.

    Returns:
        bool: Whether the script is a pay to stake script using the passed opcode.
    """
    return extractStakeScriptHash(script, stakeOpcode) is not None


def extractStakeScriptHash(script, stakeOpcode):
    """
    extractStakeScriptHash extracts a script hash from the passed public key
    script if it is a standard pay-to-script-hash script tagged with the provided
    stake opcode. It will return None otherwise.

    Args:
        script (ByteArray): The script to check.
        stakeOpcode (int): An opcode for the type of stake transaction.

    Returns:
        ByteArray: The script hash or None.
    """
    if (
        len(script) == 24
        and script[0] == stakeOpcode
        and script[1] == opcode.OP_HASH160
        and script[2] == opcode.OP_DATA_20
        and script[23] == opcode.OP_EQUAL
    ):
        return script[3:23]
    return None


def extractStakePubKeyHash(script, stakeOpcode):
    """
    extractStakePubKeyHash extracts the public key hash from the passed script if
    it is a standard stake-tagged pay-to-pubkey-hash script with the provided
    stake opcode.  It will return nil otherwise.
    """
    # A stake-tagged pay-to-pubkey-hash is of the form:
    #   <stake opcode> <standard-pay-to-pubkey-hash script>

    # The script can't possibly be a stake-tagged pay-to-pubkey-hash if it
    # doesn't start with the given stake opcode.  Fail fast to avoid more work
    # below.
    if len(script) < 1 or script[0] != stakeOpcode:
        return None
    return extractPubKeyHash(script[1:])


def isStakeSubmissionScript(scriptVersion, script):
    """
    isStakeSubmissionScript returns whether or not the passed script is a
    supported stake submission script.

    NOTE: This function is only valid for version 0 scripts.  It will always
    return false for other script versions.
    """
    # The only currently supported script version is 0.
    if scriptVersion != 0:
        return False

    # The only supported stake submission scripts are pay-to-pubkey-hash and
    # pay-to-script-hash tagged with the stake submission opcode.
    stakeOpcode = opcode.OP_SSTX
    return (
        extractStakePubKeyHash(script, stakeOpcode) is not None
        or extractStakeScriptHash(script, stakeOpcode) is not None
    )


def isStakeGenScript(scriptVersion, script):
    """
    isStakeGenScript returns whether or not the passed script is a supported
    stake generation script.

    NOTE: This function is only valid for version 0 scripts.  It will always
    return false for other script versions.
    """
    # The only currently supported script version is 0.
    if scriptVersion != 0:
        return False

    # The only supported stake generation scripts are pay-to-pubkey-hash and
    # pay-to-script-hash tagged with the stake submission opcode.
    stakeOpcode = opcode.OP_SSGEN
    return (
        extractStakePubKeyHash(script, stakeOpcode) is not None
        or extractStakeScriptHash(script, stakeOpcode) is not None
    )


def isStakeRevocationScript(scriptVersion, script):
    """
    isStakeRevocationScript returns whether or not the passed script is a
    supported stake revocation script.

    NOTE: This function is only valid for version 0 scripts.  It will always
    return false for other script versions.
    """
    # The only currently supported script version is 0.
    if scriptVersion != 0:
        return False

    # The only supported stake revocation scripts are pay-to-pubkey-hash and
    # pay-to-script-hash tagged with the stake submission opcode.
    stakeOpcode = opcode.OP_SSRTX
    return (
        extractStakePubKeyHash(script, stakeOpcode) is not None
        or extractStakeScriptHash(script, stakeOpcode) is not None
    )


def isStakeChangeScript(scriptVersion, script):
    """
    isStakeChangeScript returns whether or not the passed script is a supported
    stake change script.

    NOTE: This function is only valid for version 0 scripts.  It will always
    return false for other script versions.
    """
    # The only currently supported script version is 0.
    if scriptVersion != 0:
        return False

    # The only supported stake change scripts are pay-to-pubkey-hash and
    # pay-to-script-hash tagged with the stake submission opcode.
    stakeOpcode = opcode.OP_SSTXCHANGE
    return (
        extractStakePubKeyHash(script, stakeOpcode) is not None
        or extractStakeScriptHash(script, stakeOpcode) is not None
    )


def getStakeOutSubclass(pkScript):
    """
    getStakeOutSubclass extracts the subclass (P2PKH or P2SH) from a stake
    output.

    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    scriptVersion = 0
    err = checkScriptParses(scriptVersion, pkScript)
    if err is not None:
        raise err

    scriptClass = getScriptClass(scriptVersion, pkScript)
    if scriptTree(scriptClass) != wire.TxTreeStake:
        raise DecredError("not a stake output")

    return getScriptClass(scriptVersion, pkScript[1:])


class MultiSigDetails:
    """
    MultiSigDetails houses details extracted from a standard multisig script.
    """

    def __init__(self, pubkeys, numPubKeys, requiredSigs, valid):
        self.requiredSigs = requiredSigs
        self.numPubKeys = numPubKeys
        self.pubKeys = pubkeys
        self.valid = valid


def invalidMSDetails():
    return MultiSigDetails([], 0, [], False)


def extractMultisigScriptDetails(scriptVersion, script, extractPubKeys):
    """
    extractMultisigScriptDetails attempts to extract details from the passed
    script if it is a standard multisig script.  The returned details struct will
    have the valid flag set to false otherwise.

    The extract pubkeys flag indicates whether or not the pubkeys themselves
    should also be extracted and is provided because extracting them results in
    an allocation that the caller might wish to avoid.  The pubKeys member of
    the returned details struct will be nil when the flag is false.

    NOTE: This function is only valid for version 0 scripts.  The returned
    details struct will always be empty and have the valid flag set to false for
    other script versions.
    """
    # The only currently supported script version is 0.
    if scriptVersion != 0:
        return invalidMSDetails()

    # A multi-signature script is of the form:
    #  NUM_SIGS PUBKEY PUBKEY PUBKEY ... NUM_PUBKEYS OP_CHECKMULTISIG

    # The script can't possibly be a multisig script if it doesn't end with
    # OP_CHECKMULTISIG or have at least two small integer pushes preceding it.
    # Fail fast to avoid more work below.
    if len(script) < 3 or script[len(script) - 1] != opcode.OP_CHECKMULTISIG:
        return invalidMSDetails()
    # The first opcode must be a small integer specifying the number of
    # signatures required.
    tokenizer = ScriptTokenizer(scriptVersion, script)
    if not tokenizer.next() or not isSmallInt(tokenizer.opcode()):
        return invalidMSDetails()
    requiredSigs = asSmallInt(tokenizer.opcode())
    # The next series of opcodes must either push public keys or be a small
    # integer specifying the number of public keys.
    numPubkeys = 0
    pubkeys = []
    while tokenizer.next():
        data = tokenizer.data()
        if not isStrictPubKeyEncoding(data):
            break
        numPubkeys += 1
        if extractPubKeys:
            pubkeys.append(data)
    if tokenizer.done():
        return invalidMSDetails()
    # The next opcode must be a small integer specifying the number of public
    # keys required.
    op = tokenizer.opcode()
    if not isSmallInt(op) or asSmallInt(op) != numPubkeys:
        return invalidMSDetails()

    # There must only be a single opcode left unparsed which will be
    # OP_CHECKMULTISIG per the check above.
    if len(tokenizer.script) - tokenizer.byteIndex() != 1:
        return invalidMSDetails()
    return MultiSigDetails(pubkeys, numPubkeys, requiredSigs, True)


def isMultisigScript(scriptVersion, script):
    """
    isMultisigScript returns whether or not the passed script is a standard
    multisig script.

    NOTE: This function is only valid for version 0 scripts.  It will always
    return false for other script versions.
    """
    # Since this is only checking the form of the script, don't extract the
    # public keys to avoid the allocation.
    details = extractMultisigScriptDetails(scriptVersion, script, False)
    return details.valid


def isNullDataScript(scriptVersion, script):
    """
    isNullDataScript returns whether or not the passed script is a standard
    null data script.

    NOTE: This function is only valid for version 0 scripts.  It will always
    return false for other script versions.
    """
    # The only currently supported script version is 0.
    if scriptVersion != 0:
        return False

    # A null script is of the form:
    #  OP_RETURN <optional data>
    #
    # Thus, it can either be a single OP_RETURN or an OP_RETURN followed by a
    # data push up to MaxDataCarrierSize bytes.

    # The script can't possibly be a null data script if it doesn't start
    # with OP_RETURN.  Fail fast to avoid more work below.
    if len(script) < 1 or script[0] != opcode.OP_RETURN:
        return False

    # Single OP_RETURN.
    if len(script) == 1:
        return True

    # OP_RETURN followed by data push up to MaxDataCarrierSize bytes.
    tokenizer = ScriptTokenizer(scriptVersion, script[1:])

    return (
        tokenizer.next()
        and tokenizer.done()
        and (
            isSmallInt(tokenizer.opcode()) or tokenizer.opcode() <= opcode.OP_PUSHDATA4
        )
        and len(tokenizer.data()) <= MaxDataCarrierSize
    )


def isNullOutpoint(tx):
    """
    isNullOutpoint determines whether or not a previous transaction output point
    is set.
    """
    nullInOP = tx.txIn[0].previousOutPoint
    if (
        nullInOP.index == wire.MaxUint32
        and nullInOP.hash == ByteArray(0, length=HASH_SIZE)
        and nullInOP.tree == wire.TxTreeRegular
    ):
        return True

    return False


def isNullFraudProof(tx):
    """
    isNullFraudProof determines whether or not a previous transaction fraud proof
    is set.
    """
    txIn = tx.txIn[0]
    if txIn.blockHeight != wire.NullBlockHeight:
        return False
    elif txIn.blockIndex != wire.NullBlockIndex:
        return False

    return True


def isStakeBase(tx):
    """
    Whether or not a tx could be considered as having a topically valid stake
    base present.
    """
    # A stake base (SSGen) must only have two transaction inputs.
    if len(tx.txIn) != 2:
        return False

    # The previous output of a coin base must have a max value index and
    # a zero hash, as well as null fraud proofs.
    if not isNullOutpoint(tx):
        return False

    if not isNullFraudProof(tx):
        return False

    return True


def isSSGen(tx):
    """
    IsSSGen returns whether or not a transaction is a stake submission generation
    transaction.  These are also known as votes.
    """
    try:
        checkSSGen(tx)

    except Exception as e:
        log.debug("isSSGen: {}".format(e))

    else:
        return True


def checkSSGen(tx):
    """
    CheckSSGen returns an error if a transaction is not a stake submission
    generation transaction.  It does some simple validation steps to make sure
    the number of inputs, number of outputs, and the input/output scripts are
    valid.

    This does NOT check to see if the subsidy is valid or whether or not the
    value of input[0] + subsidy = value of the outputs.

    SSGen transactions are specified as below.
    Inputs:
    Stakebase null input [index 0]
    SStx-tagged output [index 1]

    Outputs:
    OP_RETURN push of 40 bytes containing: [index 0]
        i. 32-byte block header of block being voted on.
        ii. 8-byte int of this block's height.
    OP_RETURN push of 2 bytes containing votebits [index 1]
    SSGen-tagged output to address from SStx-tagged output's tx index output 1
        [index 2]
    SSGen-tagged output to address from SStx-tagged output's tx index output 2
        [index 3]
    ...
    SSGen-tagged output to address from SStx-tagged output's tx index output
        MaxInputsPerSStx [index MaxOutputsPerSSgen - 1]
    """
    # Check to make sure there aren't too many or too few inputs.
    if len(tx.txIn) != NumInputsPerSSGen:
        raise DecredError("SSgen tx has an invalid number of inputs")

    # Check to make sure there aren't too many outputs.
    if len(tx.txOut) > MaxOutputsPerSSGen:
        raise DecredError("SSgen tx has too many outputs")

    # Check to make sure there are enough outputs.
    if len(tx.txOut) < 2:
        raise DecredError("SSgen tx does not have enough outputs")

    # Ensure that the first input is a stake base null input.
    # Also checks to make sure that there aren't too many or too few inputs.
    if not isStakeBase(tx):
        raise DecredError(
            "SSGen tx did not include a stakebase in the zeroeth input position"
        )

    # Check to make sure that the output used as input came from TxTreeStake.
    for i, txin in enumerate(tx.txIn):
        # Skip the stakebase
        if i == 0:
            continue

        if txin.previousOutPoint.index != 0:
            raise DecredError(
                "SSGen used an invalid input idx (got {}, want 0)".format(
                    txin.previousOutPoint.index
                )
            )

        if txin.previousOutPoint.tree != wire.TxTreeStake:
            raise DecredError("SSGen used a non-stake input")

    # Check to make sure that all output scripts are the consensus version.
    for txOut in tx.txOut:
        if txOut.version != consensusVersion:
            raise DecredError("invalid script version found in txOut")

    # Ensure the number of outputs is equal to the number of inputs found in
    # the original SStx + 2.
    # TODO: Do this in validate, requires DB and valid chain.

    # Ensure that the second input is an SStx tagged output.
    # TODO: Do this in validate, as we don't want to actually lookup
    # old tx here.  This function is for more general sorting.

    # Ensure that the first output is an OP_RETURN push.
    zeroethOutputVersion = tx.txOut[0].version
    zeroethOutputScript = tx.txOut[0].pkScript
    if getScriptClass(zeroethOutputVersion, zeroethOutputScript) != NullDataTy:
        raise DecredError(
            "First SSGen output should have been an OP_RETURN data push, but was not"
        )

    # Ensure that the first output is the correct size.
    if len(zeroethOutputScript) != SSGenBlockReferenceOutSize:
        raise DecredError(
            "First SSGen output should have been {} bytes long, but was not".format(
                SSGenBlockReferenceOutSize
            )
        )

    # The OP_RETURN output script prefix for block referencing should
    # conform to the standard.
    if zeroethOutputScript[:2] != validSSGenReferenceOutPrefix:
        raise DecredError("First SSGen output had an invalid prefix")

    # Ensure that the block header hash given in the first 32 bytes of the
    # OP_RETURN push is a valid block header and found in the main chain.
    # TODO: This is validate level stuff, do this there.

    # Ensure that the second output is an OP_RETURN push.
    firstOutputVersion = tx.txOut[1].version
    firstOutputScript = tx.txOut[1].pkScript
    if getScriptClass(firstOutputVersion, firstOutputScript) != NullDataTy:
        raise DecredError(
            "Second SSGen output should have been an OP_RETURN data push, but was not"
        )

    # The length of the output script should be between 4 and 77 bytes long.
    if (
        len(firstOutputScript) < SSGenVoteBitsOutputMinSize
        or len(firstOutputScript) > SSGenVoteBitsOutputMaxSize
    ):
        raise DecredError(
            "SSGen votebits output at output index 1 was"
            " a NullData (OP_RETURN) push of the wrong size"
        )

    # The OP_RETURN output script prefix for voting should conform to the
    # standard.
    minPush = validSSGenVoteOutMinPrefix[1]
    maxPush = minPush + (MaxSingleBytePushLength - minPush)
    pushLen = firstOutputScript[1]
    pushLengthValid = pushLen >= minPush and pushLen <= maxPush
    # The first byte should be OP_RETURN, while the second byte should be a
    # valid push length.
    if firstOutputScript[0] != validSSGenVoteOutMinPrefix[0] or not pushLengthValid:
        raise DecredError("Second SSGen output had an invalid prefix")

    # Ensure that the tx height given in the last 8 bytes is StakeMaturity
    # many blocks ahead of the block in which that SStx appears, otherwise
    # this ticket has failed to mature and the SStx must be invalid.
    # TODO: This is validate level stuff, do this there.

    # Ensure that the remaining outputs are OP_SSGEN tagged.
    for i, outTx in enumerate(tx.txOut[2:]):
        scrVersion = outTx.version
        rawScript = outTx.pkScript

        # The script should be a OP_SSGEN tagged output.
        if getScriptClass(scrVersion, rawScript) != StakeGenTy:
            raise DecredError(
                f"SSGen tx output at output index {i + 2}"
                " was not an OP_SSGEN tagged output"
            )


def isSStx(tx):
    """
    isSSTx returns whether or not a transaction is a stake submission
    transaction. These are also known as tickets.

    Args:
        tx (MsgTx): A msgtx.MsgTx object.

    Returns:
        bool: Whether the tx is a ticket purchase.
    """
    try:
        checkSStx(tx)

    except Exception as e:
        log.debug("isSStx: {}".format(e))

    else:
        return True


def checkSStx(tx):
    """
    checkSStx returns an error if a transaction is not a stake submission
    transaction.  It does some simple validation steps to make sure the number of
    inputs, number of outputs, and the input/output scripts are valid.

    SStx transactions are specified as below.
    Inputs:
    untagged output 1 [index 0]
    untagged output 2 [index 1]
    ...
    untagged output MaxInputsPerSStx [index MaxInputsPerSStx-1]

    Outputs:
    OP_SSTX tagged output [index 0]
    OP_RETURN push of input 1's address for reward receiving [index 1]
    OP_SSTXCHANGE tagged output for input 1 [index 2]
    OP_RETURN push of input 2's address for reward receiving [index 3]
    OP_SSTXCHANGE tagged output for input 2 [index 4]
    ...
    OP_RETURN push of input MaxInputsPerSStx's address for reward receiving
        [index (MaxInputsPerSStx*2)-2]
    OP_SSTXCHANGE tagged output [index (MaxInputsPerSStx*2)-1]

    The output OP_RETURN pushes should be of size 20 bytes (standard address).

    Args:
        tx (MsgTx): A msgtx.MsgTx object.
    """
    # Check to make sure there aren't too many inputs.
    # CheckTransactionSanity already makes sure that number of inputs is
    # greater than 0, so no need to check that.
    if len(tx.txIn) > MaxInputsPerSStx:
        raise DecredError("SStx has too many inputs")

    # Check to make sure there aren't too many outputs.
    if len(tx.txOut) > MaxOutputsPerSStx:
        raise DecredError("SStx has too many outputs")

    # Check to make sure there are some outputs.
    if len(tx.txOut) == 0:
        raise DecredError("SStx has no outputs")

    # Check to make sure that all output scripts are the consensus version.
    for idx, txOut in enumerate(tx.txOut):
        if txOut.version != consensusVersion:
            raise DecredError("invalid script version found in txOut idx %d" % idx)

    # Ensure that the first output is tagged OP_SSTX.
    if getScriptClass(tx.txOut[0].version, tx.txOut[0].pkScript) != StakeSubmissionTy:
        raise DecredError(
            "First SStx output should have been OP_SSTX tagged, but it was not"
        )

    # Ensure that the number of outputs is equal to the number of inputs
    # + 1.
    if (len(tx.txIn) * 2 + 1) != len(tx.txOut):
        raise DecredError(
            "The number of inputs in the SStx tx was not the number of outputs/2 - 1"
        )

    # Ensure that the rest of the odd outputs are 28-byte OP_RETURN pushes that
    # contain putative pubkeyhashes, and that the rest of the odd outputs are
    # OP_SSTXCHANGE tagged.
    for outTxIndex in range(1, len(tx.txOut)):
        scrVersion = tx.txOut[outTxIndex].version
        rawScript = tx.txOut[outTxIndex].pkScript

        # Check change outputs.
        if outTxIndex % 2 == 0:
            if getScriptClass(scrVersion, rawScript) != StakeSubChangeTy:
                raise DecredError(
                    "SStx output at output index %d was not an sstx change output",
                    outTxIndex,
                )
            continue

        # Else (odd) check commitment outputs.  The script should be a
        # NullDataTy output.
        if getScriptClass(scrVersion, rawScript) != NullDataTy:
            raise DecredError(
                "SStx output at output index %d was not a NullData (OP_RETURN) push",
                outTxIndex,
            )

        # The length of the output script should be between 32 and 77 bytes long.
        if len(rawScript) < SStxPKHMinOutSize or len(rawScript) > SStxPKHMaxOutSize:
            raise DecredError(
                "SStx output at output index %d was a NullData (OP_RETURN) push"
                " of the wrong size",
                outTxIndex,
            )


def asSmallInt(op):
    """
    asSmallInt returns the passed opcode, which must be true according to
    isSmallInt(), as an integer.

    Args:
        op (int): An opcode.

    Returns:
        int: The opcode as an integer.
    """
    if not isSmallInt(op):
        raise DecredError(f"asSmallInt:{op} is not a small int")
    if op == opcode.OP_0:
        return 0
    return op - (opcode.OP_1 - 1)


def isSmallInt(op):
    """
    isSmallInt returns whether or not the opcode is considered a small integer,
    which is an OP_0, or OP_1 through OP_16.

    NOTE: This function is only valid for version 0 opcodes.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    return op == opcode.OP_0 or (op >= opcode.OP_1 and op <= opcode.OP_16)


def isStrictPubKeyEncoding(pubKey):
    """
    isStrictPubKeyEncoding returns whether or not the passed public key adheres
    to the strict encoding requirements.
    """
    if len(pubKey) == 33 and (pubKey[0] == 0x02 or pubKey[0] == 0x03):
        # Compressed
        return True
    if len(pubKey) == 65 and pubKey[0] == 0x04:
        # Uncompressed
        return True
    return False


def payToAddrScript(addr):
    """
    PayToAddrScript creates a new script to pay a transaction output to a the
    specified address.

    Args:
        addr (Address): An address.

    Returns:
        ByteArray: The pay to address script.
    """
    if isinstance(addr, addrlib.AddressPubKeyHash):
        if addr.sigType == crypto.STEcdsaSecp256k1:
            return payToPubKeyHashScript(addr.scriptAddress())
        elif addr.sigType == crypto.STEd25519:
            # return payToPubKeyHashEdwardsScript(addr.ScriptAddress())
            raise NotImplementedError("Edwards signatures not implemented")
        elif addr.sigType == crypto.STSchnorrSecp256k1:
            # return payToPubKeyHashSchnorrScript(addr.ScriptAddress())
            raise NotImplementedError("Schnorr signatures not implemented")
        raise NotImplementedError("unknown signature type %d" % addr.sigType)

    elif isinstance(addr, addrlib.AddressScriptHash):
        return payToScriptHashScript(addr.scriptAddress())

    elif isinstance(addr, addrlib.AddressSecpPubKey):
        return payToPubKeyScript(addr.scriptAddress())

    elif isinstance(addr, addrlib.AddressEdwardsPubKey):
        # return payToEdwardsPubKeyScript(addr.ScriptAddress())
        raise NotImplementedError("Edwards signatures not implemented")

    elif isinstance(addr, addrlib.AddressSecSchnorrPubKey):
        # return payToSchnorrPubKeyScript(addr.ScriptAddress())
        raise NotImplementedError("Schnorr signatures not implemented")

    raise NotImplementedError(
        "unable to generate payment script for unsupported address type %s" % type(addr)
    )


def payToPubKeyHashScript(pkHash):
    """
    payToAddrScript creates a new script to pay a transaction output to a the
    specified address.

    Args:
        pkHash (ByteArray): The pubkey hash to pay to.

    Returns:
        ByteArray: The script that pays to the pubkey hash.
    """
    if len(pkHash) != crypto.RIPEMD160_SIZE:
        raise DecredError(
            f"cannot create script with pubkey hash length {pkHash},"
            f" expected length {crypto.RIPEMD160_SIZE}"
        )
    script = ByteArray(b"")
    script += opcode.OP_DUP
    script += opcode.OP_HASH160
    script += addData(pkHash)
    script += opcode.OP_EQUALVERIFY
    script += opcode.OP_CHECKSIG
    return script


def payToScriptHashScript(scriptHash):
    """
    payToScriptHashScript creates a new script to pay a transaction output to a
    script hash. It is expected that the input is a valid hash.

    Args:
        scriptHash (ByteArray): The script hash to pay to.

    Returns:
        ByteArray: The script that pays to the script hash.
    """
    if len(scriptHash) != crypto.RIPEMD160_SIZE:
        raise DecredError(
            f"script hash must be {crypto.RIPEMD160_SIZE}"
            f" bytes but is {len(scriptHash)}"
        )
    script = ByteArray("")
    script += opcode.OP_HASH160
    script += addData(scriptHash)
    script += opcode.OP_EQUAL
    return script


def payToPubKeyScript(serializedPubKey):
    """
    payToPubkeyScript creates a new script to pay a transaction output to a
    public key. It is expected that the input is a valid pubkey.

    Args:
        serializedPubKey (ByteArray): The pubkey bytes to pay to.

    Returns:
        ByteArray: The script that pays to the pubkey.
    """
    if not isStrictPubKeyEncoding(serializedPubKey):
        raise DecredError(f"serialized pubkey has incorrect encoding")
    script = ByteArray("")
    script += addData(serializedPubKey)
    script += opcode.OP_CHECKSIG
    return script


def payToStakePKHScript(pkh, stakeCode):
    """
    Create a new script to pay a transaction for a ticket purchase with a pubkey
    hash.

    Args:
        pkh (ByteArray): A pubkey hash.
        stakeCode (int): An op code for the type of stake submission transaction.
            SSTX, SSTXCHANGE, or SSRTX.

    Returns:
        ByteArray: The script that pays to the pubkey hash of the address.
    """
    if len(pkh) != crypto.RIPEMD160_SIZE:
        raise DecredError(
            f"pubkey hash must be {crypto.RIPEMD160_SIZE} bytes but is {len(pkh)}"
        )
    if stakeCode not in (opcode.OP_SSTX, opcode.OP_SSTXCHANGE, opcode.OP_SSRTX):
        raise DecredError(
            f"stake code is not sstx, sstxchange, or ssrtx: {hex(stakeCode)}"
        )
    script = ByteArray(stakeCode)
    script += opcode.OP_DUP
    script += opcode.OP_HASH160
    script += addData(pkh)
    script += opcode.OP_EQUALVERIFY
    script += opcode.OP_CHECKSIG
    return script


def payToStakeSHScript(sh, stakeCode):
    """
    Create a new script to pay a transaction for a ticket purchase with a script
    hash.

    Args:
        sh (ByteArray): A script hash.
        stakeCode (int): An op code for the type of stake submission transaction.
            SSTX, SSTXCHANGE, or SSRTX.

    Returns:
        ByteArray: The script that pays to the script hash of the address.
    """
    if len(sh) != crypto.RIPEMD160_SIZE:
        raise DecredError(
            f"script hash must be {crypto.RIPEMD160_SIZE} bytes but is {len(sh)}"
        )
    if stakeCode not in (opcode.OP_SSTX, opcode.OP_SSTXCHANGE, opcode.OP_SSRTX):
        raise DecredError(
            f"stake code is not sstx, sstxchange, or ssrtx: {hex(stakeCode)}"
        )
    script = ByteArray(stakeCode)
    script += opcode.OP_HASH160
    script += addData(sh)
    script += opcode.OP_EQUAL
    return script


def multiSigScript(addrs, nRequired):
    """
    Create a multisig script for nRequired of addrs.

    Args:
        addrs (list(AddressSecpPubKey)): Addresses that make up the script.
        nRequired (int): The number of signatures required to spend.

    Returns:
        ByteArray: A multisig script.
    """
    if len(addrs) < nRequired:
        raise DecredError(
            f"unable to generate multisig script with {nRequired} required signatures"
            f" when there are only {len(addrs)} public keys available"
        )
    script = ByteArray(addInt(nRequired))
    for addr in addrs:
        script += addData(addr.scriptAddress())
    script += addInt(len(addrs))
    script += opcode.OP_CHECKMULTISIG
    return script


def payToSStx(addr):
    """
    payToSStx creates a new script to pay a transaction output to a script hash or
    public key hash, but tags the output with OP_SSTX. For use in constructing
    valid SStxs.
    """
    # Only pay to pubkey hash and pay to script hash are
    # supported.
    scriptType = PubKeyHashTy
    if isinstance(addr, addrlib.AddressPubKeyHash):
        if addr.sigType != crypto.STEcdsaSecp256k1:
            raise NotImplementedError(
                "unable to generate payment script for "
                "unsupported digital signature algorithm"
            )
    elif isinstance(addr, addrlib.AddressScriptHash):
        scriptType = ScriptHashTy
    else:
        raise NotImplementedError(
            "unable to generate payment script for "
            "unsupported address type %s" % type(addr)
        )

    if scriptType == PubKeyHashTy:
        return payToStakePKHScript(addr.scriptAddress(), opcode.OP_SSTX)
    return payToStakeSHScript(addr.scriptAddress(), opcode.OP_SSTX)


def generateSStxAddrPush(addr, amount, limits):
    """
    generateSStxAddrPush generates an OP_RETURN push for SSGen payment addresses in
    an SStx.
    """
    # Only pay to pubkey hash and pay to script hash are
    # supported.
    scriptType = PubKeyHashTy
    if isinstance(addr, addrlib.AddressPubKeyHash):
        if addr.sigType != crypto.STEcdsaSecp256k1:
            raise NotImplementedError(
                "unable to generate payment script for "
                "unsupported digital signature algorithm"
            )
    elif isinstance(addr, addrlib.AddressScriptHash):
        scriptType = ScriptHashTy
    else:
        raise NotImplementedError(
            "unable to generate payment script for unsupported address type %s"
            % type(addr)
        )

    # Concatenate the prefix, pubkeyhash, and amount.
    adBytes = addr.scriptAddress()
    adBytes += ByteArray(amount, length=8).littleEndian()
    adBytes += ByteArray(limits, length=2).littleEndian()

    # Set the bit flag indicating pay to script hash.
    if scriptType == ScriptHashTy:
        adBytes[27] |= 1 << 7

    script = ByteArray(opcode.OP_RETURN)
    script += addData(adBytes)
    return script


def payToSStxChange(addr):
    """
    payToSStxChange creates a new script to pay a transaction output to a
    public key hash, but tags the output with OP_SSTXCHANGE. For use in constructing
    valid SStxs.

    Args:
        addr (Address): An address. AddressPubKeyHash or AddressScriptHash.

    Returns:
        ByteArray: The PayToSStxChange script.
    """
    # Only pay to pubkey hash and pay to script hash are
    # supported.
    scriptType = PubKeyHashTy
    if isinstance(addr, addrlib.AddressPubKeyHash):
        if addr.sigType != crypto.STEcdsaSecp256k1:
            raise NotImplementedError(
                "unable to generate payment script for "
                "unsupported digital signature algorithm"
            )
    elif isinstance(addr, addrlib.AddressScriptHash):
        scriptType = ScriptHashTy
    else:
        raise NotImplementedError(
            "unable to generate payment script for unsupported address type %s",
            type(addr),
        )

    if scriptType == PubKeyHashTy:
        return payToStakePKHScript(addr.scriptAddress(), opcode.OP_SSTXCHANGE)
    return payToStakeSHScript(addr.scriptAddress(), opcode.OP_SSTXCHANGE)


def makePayToAddrScript(addrStr, netParams):
    addr = addrlib.decodeAddress(addrStr, netParams)
    return payToAddrScript(addr)


def int2octets(v, rolen):
    """
    Converts the passed integer into a byte array with length of rolen in big
    endian notation padded with zeros. Overflow is discarded.

    https://tools.ietf.org/html/rfc6979#section-2.3.3

    Args:
        v (int): Integer value to convert.
        rolen (int): Number of octects, or bytes, to return.

    Returns:
        ByteArray: The integer in bytes.
    """
    out = ByteArray(v)

    # left pad with zeros if it's too short
    if len(out) < rolen:
        out2 = ByteArray(0, length=rolen)
        out2[rolen - len(out)] = out
        return out2

    # drop most significant bytes if it's too long
    if len(out) > rolen:
        out2 = ByteArray(0, length=rolen)
        out2[0] = out[len(out) - rolen :]
        return out2
    return out


def bits2octets(bits, rolen):
    """
    Converts bits into octects modulo Curve.N, padded with zeros. Overflow is
    discarded.

    https://tools.ietf.org/html/rfc6979#section-2.3.4

    Args:
        bits (ByteArray): Bytes to convert.
        rolen (int): Number of digits to allow.

    Returns:
        ByteArray: The bytes modulo Curve.N
    """
    z1 = hashToInt(bits)
    z2 = z1 - Curve.N
    if z2 < 0:
        return int2octets(z1, rolen)
    return int2octets(z2, rolen)


def nonceRFC6979(privKey, inHash):
    """
    nonceRFC6979 generates an ECDSA nonce (`k`) deterministically according to
    RFC 6979. It takes a 32-byte hash as an input and returns 32-byte nonce to
    be used in ECDSA algorithm.

    Args:
        privKey (ByteArray): Private key bytes.
        inHash (ByteArray): The input hash.

    Returns:
        int: The deterministic nonce.
    """
    # Truncate private key if too long.
    if len(privKey) > 32:
        privKey = privKey[:32]

    q = Curve.N
    x = privKey

    qlen = q.bit_length()
    holen = SHA256_SIZE
    rolen = (qlen + 7) >> 3
    bx = int2octets(x, rolen) + bits2octets(inHash, rolen)

    # Step B
    v = ByteArray(bytearray([1] * holen))

    # Step C (Go zeroes the all allocated memory)
    k = ByteArray(0, length=holen)

    # Step D
    k = mac(k, v + ByteArray(0x00, length=1) + bx)

    # Step E
    v = mac(k, v)

    # Step F
    k = mac(k, v + 0x01 + bx)

    # Step G
    v = mac(k, v)

    # Step H
    while True:
        # Step H1
        t = ByteArray(b"")

        # Step H2
        while len(t) * 8 < qlen:
            v = mac(k, v)
            t += v

        # Step H3
        secret = hashToInt(t)
        if secret >= 1 and secret < q:
            return secret

        k = mac(k, v + 0x00)
        v = mac(k, v)


def verifySig(pub, inHash, r, s):
    """
    verifySig verifies the signature in r, s of inHash using the public key, pub.

    Args:
        pub (PublicKey): The public key.
        inHash (byte-like): The thing being signed.
        r (int): The R-parameter of the ECDSA signature.
        s (int): The S-parameter of the ECDSA signature.

    Returns:
        bool: True if the signature verifies the key.
    """
    # See [NSA] 3.4.2
    N = Curve.N

    if r <= 0 or s <= 0:
        return False

    if r >= N or s >= N:
        return False

    e = hashToInt(inHash)

    w = crypto.modInv(s, N)

    u1 = (e * w) % N
    u2 = (r * w) % N

    x1, y1 = Curve.scalarBaseMult(u1)
    x2, y2 = Curve.scalarMult(pub.x, pub.y, u2)
    x, y = Curve.add(x1, y1, x2, y2)

    if x == 0 and y == 0:
        return False
    x = x % N
    return x == r


def signRFC6979(privateKey, inHash):
    """
    signRFC6979 generates a deterministic ECDSA signature according to RFC 6979
    and BIP 62.
    """
    N = Curve.N
    k = nonceRFC6979(privateKey, inHash)

    inv = crypto.modInv(k, N)
    r = Curve.scalarBaseMult(k)[0] % N

    if r == 0:
        raise DecredError("calculated R is zero")

    e = hashToInt(inHash)
    s = privateKey.int() * r
    s += e
    s *= inv
    s = s % N

    if (N >> 1) > 1:
        s = N - s
    if s == 0:
        raise DecredError("calculated S is zero")

    return Signature(r, s)


def putVarInt(val):
    """
    putVarInt serializes the provided number to a variable-length integer and
    according to the format described above returns the number of bytes of the
    encoded value.
    """
    if val < 0xFD:
        return ByteArray(val, length=1)

    if val <= wire.MaxUint16:
        return (
            reversed(ByteArray(0xFD, length=3))
            | ByteArray(val, length=2).littleEndian()
        )

    if val <= wire.MaxUint32:
        return (
            reversed(ByteArray(0xFE, length=5))
            | ByteArray(val, length=4).littleEndian()
        )

    return reversed(ByteArray(0xFF, length=9)) | ByteArray(val, length=8).littleEndian()


def addInt(val):
    """
    addInt returns the passed integer in a form that can be pushed to the end
    of a script.

    Args:
        val (int): The integer to format.

    Returns:
        ByteArray: The formatted integer.
    """
    b = ByteArray(b"")

    # Fast path for small integers and OP_1NEGATE.
    if val == 0:
        b += opcode.OP_0
        return b
    if val == -1 or (val >= 1 and val <= 16):
        b += opcode.OP_1 - 1 + val
        return b
    return addData(scriptNumBytes(val))


def addData(data):
    """
    Prefaces data with the correct opcode when adding it to the stack.

    Args:
        value (ByteArray): Data to add.
    Returns:
        ByteArray: The data preceded with the correct opcode.
    """
    dataLen = len(data) if data else 0
    b = ByteArray(b"")

    # When the data consists of a single number that can be represented
    # by one of the "small integer" opcodes, use that opcode instead of
    # a data push opcode followed by the number.
    if dataLen == 0 or (dataLen == 1 and data[0] == 0):
        b += opcode.OP_0
        return b
    elif dataLen == 1 and data[0] <= 16:
        b += opcode.OP_1 - 1 + data[0]
        return b
    elif dataLen == 1 and data[0] == 0x81:
        b += opcode.OP_1NEGATE
        return b

    # Use one of the OP_DATA_# opcodes if the length of the data is small
    # enough so the data push instruction is only a single byte.
    # Otherwise, choose the smallest possible OP_PUSHDATA# opcode that
    # can represent the length of the data.
    if dataLen < opcode.OP_PUSHDATA1:
        b += (opcode.OP_DATA_1 - 1) + dataLen
    elif dataLen <= 0xFF:
        b += opcode.OP_PUSHDATA1
        b += dataLen
    elif dataLen <= 0xFFFF:
        b += opcode.OP_PUSHDATA2
        b += ByteArray(dataLen).littleEndian()
    else:
        b += opcode.OP_PUSHDATA4
        b += ByteArray(dataLen, length=4).littleEndian()
    # Append the actual data.
    b += data
    return b


def signatureScript(tx, idx, subscript, hashType, privKey, compress):
    """
    SignatureScript creates an input signature script for tx to spend coins sent
    from a previous output to the owner of privKey. tx must include all
    transaction inputs and outputs, however txin scripts are allowed to be filled
    or empty. The returned script is calculated to be used as the idx'th txin
    sigscript for tx. subscript is the PkScript of the previous output being used
    as the idx'th input. privKey is serialized in either a compressed or
    uncompressed format based on compress. This format must match the same format
    used to generate the payment address, or the script validation will fail.
    """

    sig = rawTxInSignature(tx, idx, subscript, hashType, privKey.key)

    pubKey = privKey.pub

    if compress:
        pkData = pubKey.serializeCompressed()
    else:
        pkData = pubKey.serializeUncompressed()

    script = addData(sig)
    script += addData(pkData)

    return script


def rawTxInSignature(tx, idx, subScript, hashType, key):
    """
    rawTxInSignature returns the serialized ECDSA signature for the input idx of
    the given transaction, with hashType appended to it.

    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    sigHash = calcSignatureHash(subScript, hashType, tx, idx, None)
    sig = signRFC6979(key, sigHash).serialize()
    return sig + ByteArray(hashType)


def calcSignatureHash(script, hashType, tx, idx, cachedPrefix):
    """
    CalcSignatureHash computes the signature hash for the specified input of
    the target transaction observing the desired signature hash type.  The
    cached prefix parameter allows the caller to optimize the calculation by
    providing the prefix hash to be reused in the case of SigHashAll without the
    SigHashAnyOneCanPay flag set.

    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    scriptVersion = 0
    checkScriptParses(scriptVersion, script)

    # return calcSignatureHash(script, hashType, tx, idx, cachedPrefix)

    # The SigHashSingle signature type signs only the corresponding input
    # and output (the output with the same index number as the input).
    #
    # Since transactions can have more inputs than outputs, this means it
    # is improper to use SigHashSingle on input indices that don't have a
    # corresponding output.
    if hashType & sigHashMask == SigHashSingle and idx >= len(tx.txOut):
        raise DecredError(
            "attempt to sign single input at index %d >= %d outputs"
            % (idx, len(tx.txOut))
        )

    # Choose the inputs that will be committed to based on the signature
    # hash type.
    #
    # The SigHashAnyOneCanPay flag specifies that the signature will only
    # commit to the input being signed.  Otherwise, it will commit to all
    # inputs.
    txIns = tx.txIn
    signTxInIdx = idx
    if hashType & SigHashAnyOneCanPay != 0:
        txIns = tx.txIn[idx : idx + 1]
        signTxInIdx = 0

    # The prefix hash commits to the non-witness data depending on the
    # signature hash type.  In particular, the specific inputs and output
    # semantics which are committed to are modified depending on the
    # signature hash type as follows:
    #
    # SigHashAll (and undefined signature hash types):
    #   Commits to all outputs.
    # SigHashNone:
    #   Commits to no outputs with all input sequences except the input
    #   being signed replaced with 0.
    # SigHashSingle:
    #   Commits to a single output at the same index as the input being
    #   signed.  All outputs before that index are cleared by setting the
    #   value to -1 and pkscript to nil and all outputs after that index
    #   are removed.  Like SigHashNone, all input sequences except the
    #   input being signed are replaced by 0.
    # SigHashAnyOneCanPay:
    #   Commits to only the input being signed.  Bit flag that can be
    #   combined with the other signature hash types.  Without this flag
    #   set, commits to all inputs.
    #
    # With the relevant inputs and outputs selected and the aforementioned
    # substitions, the prefix hash consists of the hash of the
    # serialization of the following fields:
    #
    # 1) txversion|(SigHashSerializePrefix<<16) (as little-endian uint32)
    # 2) number of inputs (as varint)
    # 3) per input:
    #    a) prevout hash (as little-endian uint256)
    #    b) prevout index (as little-endian uint32)
    #    c) prevout tree (as single byte)
    #    d) sequence (as little-endian uint32)
    # 4) number of outputs (as varint)
    # 5) per output:
    #    a) output amount (as little-endian uint64)
    #    b) pkscript version (as little-endian uint16)
    #    c) pkscript length (as varint)
    #    d) pkscript (as unmodified bytes)
    # 6) transaction lock time (as little-endian uint32)
    # 7) transaction expiry (as little-endian uint32)
    #
    # In addition, an optimization for SigHashAll is provided when the
    # SigHashAnyOneCanPay flag is not set.  In that case, the prefix hash
    # can be reused because only the witness data has been modified, so
    # the wasteful extra O(N^2) hash can be avoided.
    prefixHash = ByteArray(b"")
    if (
        SigHashOptimization
        and cachedPrefix is not None
        and hashType & sigHashMask == SigHashAll
        and (hashType & SigHashAnyOneCanPay).iszero()
    ):

        prefixHash = cachedPrefix
    else:
        # Choose the outputs to commit to based on the signature hash
        # type.
        #
        # As the names imply, SigHashNone commits to no outputs and
        # SigHashSingle commits to the single output that corresponds
        # to the input being signed.  However, SigHashSingle is also a
        # bit special in that it commits to cleared out variants of all
        # outputs prior to the one being signed.  This is required by
        # consensus due to legacy reasons.
        #
        # All other signature hash types, such as SighHashAll commit to
        # all outputs.  Note that this includes undefined hash types as well.
        txOuts = tx.txOut
        requiredSigs = hashType & sigHashMask
        if requiredSigs == SigHashNone:
            txOuts = []
        elif requiredSigs == SigHashSingle:
            txOuts = tx.txOut[: idx + 1]

        expectedSize = sigHashPrefixSerializeSize(hashType, txIns, txOuts, idx)

        prefixBuf = ByteArray(b"")

        # Commit to the version and hash serialization type.
        prefixBuf += ByteArray(
            tx.version | (SigHashSerializePrefix << 16), length=4
        ).littleEndian()

        # Commit to the relevant transaction inputs.
        prefixBuf += putVarInt(len(txIns))
        for txInIdx, txIn in enumerate(txIns):
            # Commit to the outpoint being spent.
            prevOut = txIn.previousOutPoint
            prefixBuf += prevOut.hash
            prefixBuf += ByteArray(prevOut.index, length=4).littleEndian()  # uint32
            prefixBuf += ByteArray(prevOut.tree, length=1)

            # Commit to the sequence.  In the case of SigHashNone
            # and SigHashSingle, commit to 0 for everything that is
            # not the input being signed instead.
            sequence = txIn.sequence
            if (
                (hashType & sigHashMask) == SigHashNone
                or (hashType & sigHashMask) == SigHashSingle
            ) and txInIdx != signTxInIdx:
                sequence = 0
            prefixBuf += ByteArray(sequence, length=4).littleEndian()

        # Commit to the relevant transaction outputs.
        prefixBuf += putVarInt(len(txOuts))

        for txOutIdx, txOut in enumerate(txOuts):
            # Commit to the output amount, script version, and
            # public key script.  In the case of SigHashSingle,
            # commit to an output amount of -1 and a nil public
            # key script for everything that is not the output
            # corresponding to the input being signed instead.
            value = txOut.value
            pkScript = txOut.pkScript
            if hashType & sigHashMask == SigHashSingle and txOutIdx != idx:
                value = MAX_UINT64
                pkScript = b""
            prefixBuf += ByteArray(value, length=8).littleEndian()
            prefixBuf += ByteArray(txOut.version, length=2).littleEndian()
            prefixBuf += putVarInt(len(pkScript))
            prefixBuf += pkScript

        # Commit to the lock time and expiry.
        prefixBuf += ByteArray(tx.lockTime, length=4).littleEndian()
        prefixBuf += ByteArray(tx.expiry, length=4).littleEndian()
        if len(prefixBuf) != expectedSize:
            raise DecredError(
                "incorrect prefix serialization size %i != %i"
                % (len(prefixBuf), expectedSize)
            )
        prefixHash = hashH(prefixBuf.bytes())

    # The witness hash commits to the input witness data depending on
    # whether or not the signature hash type has the SigHashAnyOneCanPay
    # flag set.  In particular the semantics are as follows:
    #
    # SigHashAnyOneCanPay:
    #   Commits to only the input being signed.  Without this flag set,
    #   commits to all inputs with the reference scripts cleared by setting
    #   them to nil.
    #
    # With the relevant inputs selected, and the aforementioned substitutions,
    # the witness hash consists of the hash of the serialization of the
    # following fields:
    #
    # 1) txversion|(SigHashSerializeWitness<<16) (as little-endian uint32)
    # 2) number of inputs (as varint)
    # 3) per input:
    #    a) length of prevout pkscript (as varint)
    #    b) prevout pkscript (as unmodified bytes)

    expectedSize = sigHashWitnessSerializeSize(txIns, script)
    witnessBuf = ByteArray(b"")

    # Commit to the version and hash serialization type.
    version = ByteArray(tx.version, length=4) | (SigHashSerializeWitness << 16)
    witnessBuf += version.littleEndian()

    # Commit to the relevant transaction inputs.
    witnessBuf += putVarInt(len(txIns))
    for txInIdx in range(len(txIns)):
        # Commit to the input script at the index corresponding to the
        # input index being signed.  Otherwise, commit to a nil script
        # instead.
        commitScript = script
        if txInIdx != signTxInIdx:
            commitScript = b""
        witnessBuf += putVarInt(len(commitScript))
        witnessBuf += commitScript
    if len(witnessBuf) != expectedSize:
        raise DecredError(
            "incorrect witness serialization size %i != %i"
            % (len(witnessBuf), expectedSize)
        )
    witnessHash = hashH(witnessBuf.bytes())

    # The final signature hash (message to sign) is the hash of the
    # serialization of the following fields:
    #
    # 1) the hash type (as little-endian uint32)
    # 2) prefix hash (as produced by hash function)
    # 3) witness hash (as produced by hash function)
    sigHashBuf = ByteArray(0, length=HASH_SIZE * 2 + 4)
    sigHashBuf[0] = ByteArray(hashType, length=4).littleEndian()
    sigHashBuf[4] = prefixHash
    sigHashBuf[4 + HASH_SIZE] = witnessHash
    h = hashH(sigHashBuf.bytes())
    return h


def signP2PKHMsgTx(msgtx, prevOutputs, keysource, netParams):
    """
    signP2PKHMsgTx sets the SignatureScript for every item in msgtx.TxIn.
    It must be called every time a msgtx is changed.
    Only P2PKH outputs are supported at this point.

    The passed msgtx is modified.

    Args:
        msgtx (MsgTx): The transaction to sign.
        prevOutputs (list(Credit)): A list of txscript.Credit to sign.
        keysource (Keysource): An account.KeySource source for private keys.
        netParams (module): Network parameters.
    """
    prevOutLen, txInLen = len(prevOutputs), len(msgtx.txIn)
    if prevOutLen != txInLen:
        msg = "Number of prevOutputs ({}) does not match number of tx inputs ({})"
        raise DecredError(msg.format(prevOutLen, txInLen))

    for i, output in enumerate(prevOutputs):
        # Errors don't matter here, as we only consider the
        # case where len(addrs) == 1.
        _, addrs, _ = extractPkScriptAddrs(0, output.pkScript, netParams)
        if len(addrs) != 1:
            continue
        apkh = addrs[0]
        if not isinstance(apkh, addrlib.AddressPubKeyHash):
            raise DecredError("previous output address is not P2PKH")

        privKey = keysource.priv(apkh.string())
        sigscript = signatureScript(
            msgtx, i, output.pkScript, SigHashAll, privKey, True
        )
        msgtx.txIn[i].signatureScript = sigscript


def paysHighFees(totalInput, tx):
    """
    paysHighFees checks whether the signed transaction pays insanely high fees.
    Transactions are defined as having a high fee if they pay a fee rate that is
    1000 times higher than the default fee.

    Args:
        totalInput (int): Input amount for the output transaction.
        tx (msgtx.MsgTx): the transaction to be spent.

    Returns:
        bool: Whether this transaction pays insanely high fees.
    """
    fee = totalInput - sum([op.value for op in tx.txOut])
    if fee <= 0:
        # Impossible to determine
        return False

    maxFee = calcMinRequiredTxRelayFee(1000 * DefaultRelayFeePerKb, tx.serializeSize())
    return fee > maxFee


def sigHashPrefixSerializeSize(hashType, txIns, txOuts, signIdx):
    """
    sigHashPrefixSerializeSize returns the number of bytes the passed parameters
    would take when encoded with the format used by the prefix hash portion of
    the overall signature hash.
    1) 4 bytes version/serialization type
    2) number of inputs varint
    3) per input:
       a) 32 bytes prevout hash
       b) 4 bytes prevout index
       c) 1 byte prevout tree
       d) 4 bytes sequence
    4) number of outputs varint
    5) per output:
       a) 8 bytes amount
       b) 2 bytes script version
       c) pkscript len varint (1 byte if not SigHashSingle output)
       d) N bytes pkscript (0 bytes if not SigHashSingle output)
    6) 4 bytes lock time
    7) 4 bytes expiry
    """
    numTxIns = len(txIns)
    numTxOuts = len(txOuts)
    size = (
        4
        + varIntSerializeSize(numTxIns)
        + numTxIns * (HASH_SIZE + 4 + 1 + 4)
        + varIntSerializeSize(numTxOuts)
        + numTxOuts * (8 + 2)
        + 4
        + 4
    )
    for txOutIdx, txOut in enumerate(txOuts):
        pkScript = txOut.pkScript
        if hashType & sigHashMask == SigHashSingle and txOutIdx != signIdx:
            pkScript = b""
        size += varIntSerializeSize(len(pkScript))
        size += len(pkScript)
    return size


def sigHashWitnessSerializeSize(txIns, signScript):
    """
    sigHashWitnessSerializeSize returns the number of bytes the passed parameters
    would take when encoded with the format used by the witness hash portion of
    the overall signature hash.
    """
    # 1) 4 bytes version/serialization type
    # 2) number of inputs varint
    # 3) per input:
    #    a) prevout pkscript varint (1 byte if not input being signed)
    #    b) N bytes prevout pkscript (0 bytes if not input being signed)
    #
    # NOTE: The prevout pkscript is replaced by nil for all inputs except
    # the input being signed.  Thus, all other inputs (aka numTxIns-1) commit
    # to a nil script which gets encoded as a single 0x00 byte.  This is
    # because encoding 0 as a varint results in 0x00 and there is no script
    # to write.  So, rather than looping through all inputs and manually
    # calculating the size per input, use (numTxIns - 1) as an
    # optimization.
    numTxIns = len(txIns)
    return (
        4
        + varIntSerializeSize(numTxIns)
        + (numTxIns - 1)
        + varIntSerializeSize(len(signScript))
        + len(signScript)
    )


def pubKeyHashToAddrs(pkHash, netParams):
    """
    pubKeyHashToAddrs is a convenience function to attempt to convert the
    passed hash to a pay-to-pubkey-hash address housed within an address
    list.  It is used to consolidate common code.
    """
    return [addrlib.AddressPubKeyHash(pkHash, netParams, crypto.STEcdsaSecp256k1)]


def scriptHashToAddrs(scriptHash, netParams):
    """
    scriptHashToAddrs is a convenience function to attempt to convert the passed
    hash to a pay-to-script-hash address housed within an address list.  It is
    used to consolidate common code.
    """
    return [addrlib.AddressScriptHash(scriptHash, netParams)]


def extractPkScriptAddrs(version, pkScript, netParams):
    """
    extractPkScriptAddrs returns the type of script, addresses and required
    signatures associated with the passed PkScript.  Note that it only works for
    'standard' transaction script types.  Any data such as public keys which are
    invalid are omitted from the results.

    NOTE: This function only attempts to identify version 0 scripts.  The return
    value will indicate a nonstandard script type for other script versions along
    with an invalid script version error.
    """
    if version != 0:
        raise DecredError("invalid script version")

    # Check for pay-to-pubkey-hash script.
    pkHash = extractPubKeyHash(pkScript)
    if pkHash:
        return PubKeyHashTy, pubKeyHashToAddrs(pkHash, netParams), 1

    # Check for pay-to-script-hash.
    scriptHash = extractScriptHash(pkScript)
    if scriptHash:
        return ScriptHashTy, scriptHashToAddrs(scriptHash, netParams), 1

    # Check for pay-to-alt-pubkey-hash script.
    data, sigType = extractPubKeyHashAltDetails(pkScript)
    if data:
        addrs = [addrlib.AddressPubKeyHash(data, netParams, sigType)]
        return PubkeyHashAltTy, addrs, 1

    # Check for pay-to-pubkey script.
    data = extractPubKey(pkScript)
    if data:
        pk = Curve.parsePubKey(data)
        addrs = [addrlib.AddressSecpPubKey(pk.serializeCompressed(), netParams)]
        return PubKeyTy, addrs, 1

    # Check for pay-to-alt-pubkey script.
    pk, sigType = extractPubKeyAltDetails(pkScript)
    if pk:
        raise NotImplementedError("only secp256k1 signatures are currently supported")
        # addrs = []
        # if sigType == dcrec.STEd25519:
        #     addr = addrlib.NewAddressEdwardsPubKey(pk, netParams)
        #     addrs.append(addr)

        # elif sigType == crypto.STSchnorrSecp256k1:
        #     addr = addrlib.NewAddressSecSchnorrPubKey(pk, netParams)
        #     addrs.append(addr)

        # return PubkeyAltTy, addrs, 1

    # Check for multi-signature script.
    details = extractMultisigScriptDetails(version, pkScript, True)
    if details.valid:
        # Convert the public keys while skipping any that are invalid.
        addrs = []
        for encodedPK in details.pubKeys:
            pk = Curve.parsePubKey(encodedPK)
            addrs.append(addrlib.AddressSecpPubKey(pk.serializeCompressed(), netParams))
        return MultiSigTy, addrs, details.requiredSigs

    # Check for stake submission script.  Only stake-submission-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSTX)
    if pkHash:
        return StakeSubmissionTy, pubKeyHashToAddrs(pkHash, netParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSTX)
    if scriptHash:
        return StakeSubmissionTy, scriptHashToAddrs(scriptHash, netParams), 1

    # Check for stake generation script.  Only stake-generation-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSGEN)
    if pkHash:
        return StakeGenTy, pubKeyHashToAddrs(pkHash, netParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSGEN)
    if scriptHash:
        return StakeGenTy, scriptHashToAddrs(scriptHash, netParams), 1

    # Check for stake revocation script.  Only stake-revocation-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSRTX)
    if pkHash:
        return StakeRevocationTy, pubKeyHashToAddrs(pkHash, netParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSRTX)
    if scriptHash:
        return StakeRevocationTy, scriptHashToAddrs(scriptHash, netParams), 1

    # Check for stake change script.  Only stake-change-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSTXCHANGE)
    if pkHash:
        return StakeSubChangeTy, pubKeyHashToAddrs(pkHash, netParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSTXCHANGE)
    if scriptHash:
        return StakeSubChangeTy, scriptHashToAddrs(scriptHash, netParams), 1

    # Check for null data script.
    if isNullDataScript(version, pkScript):
        # Null data transactions have no addresses or required signatures.
        return NullDataTy, [], 0

    # Don't attempt to extract addresses or required signatures for nonstandard
    # transactions.
    return NonStandardTy, [], 0


def sign(netParams, tx, idx, subScript, hashType, keysource, sigType):
    scriptClass, addresses, nrequired = extractPkScriptAddrs(
        DefaultScriptVersion, subScript, netParams
    )

    subClass = scriptClass
    isStakeType = (
        scriptClass == StakeSubmissionTy
        or scriptClass == StakeSubChangeTy
        or scriptClass == StakeGenTy
        or scriptClass == StakeRevocationTy
    )
    if isStakeType:
        subClass = getStakeOutSubclass(subScript)

    if scriptClass == PubKeyTy:
        raise NotImplementedError("P2PK signature scripts not implemented")
        # privKey = keysource.priv(addresses[0].string())
        # script = p2pkSignatureScript(tx, idx, subScript, hashType, key)
        # return script, scriptClass, addresses, nrequired, nil

    elif scriptClass == PubkeyAltTy:
        raise NotImplementedError("alt signatures not implemented")
        # privKey = keysource.priv(addresses[0].string())
        # script = p2pkSignatureScriptAlt(tx, idx, subScript, hashType, key, sigType)
        # return script, scriptClass, addresses, nrequired, nil

    elif scriptClass == PubKeyHashTy:
        privKey = keysource.priv(addresses[0].string())
        script = signatureScript(tx, idx, subScript, hashType, privKey, True)
        return script, scriptClass, addresses, nrequired

    elif scriptClass == PubkeyHashAltTy:
        raise NotImplementedError("alt signatures not implemented")
        # look up key for address
        # privKey = keysource.priv(addresses[0].string())
        # script = signatureScriptAlt(
        #     tx, idx, subScript, hashType, key, compressed, sigType)
        # return script, scriptClass, addresses, nrequired

    elif scriptClass == ScriptHashTy:
        raise NotImplementedError("script-hash script signing not implemented")
        # script = keysource.script(addresses[0])
        # return script, scriptClass, addresses, nrequired

    elif scriptClass == MultiSigTy:
        privKeys = []
        for addr in addresses:
            privKeys.append(keysource.priv(addr))
        script = signMultiSig(
            tx, idx, subScript, hashType, addresses, nrequired, privKeys
        )
        return script, scriptClass, addresses, nrequired

    elif scriptClass == StakeSubmissionTy:
        return handleStakeOutSign(
            tx,
            idx,
            subScript,
            hashType,
            keysource,
            addresses,
            scriptClass,
            subClass,
            nrequired,
        )

    elif scriptClass == StakeGenTy:
        return handleStakeOutSign(
            tx,
            idx,
            subScript,
            hashType,
            keysource,
            addresses,
            scriptClass,
            subClass,
            nrequired,
        )

    elif scriptClass == StakeRevocationTy:
        return handleStakeOutSign(
            tx,
            idx,
            subScript,
            hashType,
            keysource,
            addresses,
            scriptClass,
            subClass,
            nrequired,
        )

    elif scriptClass == StakeSubChangeTy:
        return handleStakeOutSign(
            tx,
            idx,
            subScript,
            hashType,
            keysource,
            addresses,
            scriptClass,
            subClass,
            nrequired,
        )

    elif scriptClass == NullDataTy:
        raise NotImplementedError("can't sign NULLDATA transactions")

    raise NotImplementedError("can't sign unknown transactions")


def signMultiSig(tx, idx, subScript, hashType, addresses, nRequired, privKeys):
    """
    signMultiSig signs as many of the outputs in the provided multisig script as
    possible. It returns the generated script and a boolean if the script
    fulfills the contract (i.e. nrequired signatures are provided).  Since it is
    arguably legal to not be able to sign any of the outputs, no error is
    returned.

    Args:
        tx (object): the ticket purchase MsgTx.
        idx (int): the output index that contains the multisig.
        subScript (byte-like): the multisig script.
        hashType (int): the type of hash needed
        addresses (list(object)): the addresses that make up the multisig.
        nRequired (int): the number of signatures required to fulfill the pkScript.
        privKeys (list(byte-like)): the private keys for addresses.

    Returns:
        byte-like: the signed multisig script.
    """

    # No need to add dummy in Decred.
    signed = 0
    script = ByteArray(b"")
    for idx in range(len(addresses)):

        sig = rawTxInSignature(tx, idx, subScript, hashType, privKeys[idx].key)

        script += addData(sig)
        signed += 1
        if signed == nRequired:
            break

    return script


def handleStakeOutSign(
    tx, idx, subScript, hashType, keysource, addresses, scriptClass, subClass, nrequired
):
    """
    # handleStakeOutSign is a convenience function for reducing code clutter in
    # sign. It handles the signing of stake outputs.
    """
    if subClass == PubKeyHashTy:
        privKey = keysource.priv(addresses[0].string())
        txscript = signatureScript(tx, idx, subScript, hashType, privKey, True)
        return txscript, scriptClass, addresses, nrequired
    elif subClass == ScriptHashTy:  # nocover
        # This will be needed in order to enable voting.
        raise NotImplementedError("script-hash script signing not implemented")
        # script = keysource.script(addresses[0].string())
        # return script, scriptClass, addresses, nrequired
    raise NotImplementedError("unknown subclass for stake output to sign")


def mergeScripts(
    netParams,
    tx,
    idx,
    pkScript,
    scriptClass,
    addresses,
    nRequired,
    sigScript,
    prevScript,
):
    """
    mergeScripts merges sigScript and prevScript assuming they are both
    partial solutions for pkScript spending output idx of tx. class, addresses
    and nrequired are the result of extracting the addresses from pkscript.
    The return value is the best effort merging of the two scripts. Calling this
    function with addresses, class and nrequired that do not match pkScript is
    an error and results in undefined behaviour.

    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.

    Args:
        netParams (module): Network parameters.
        tx (msgtx.Tx): Transaction that pkScript belongs to.
        idx (int): The output index that pkScript belongs to.
        pkScript (ByteArray): The script that spends output idx of tx.
        scriptClass (int): Type of script.
        addresses list(str): Addresses that comprise a multisig.
        nRequired (int): Number of addresses required for a multisig.
        sigScript (ByteArray): The signed script.
        prevScript (ByteArray): The previous script.
    """
    # TODO(oga) the scripthash and multisig paths here are overly
    # inefficient in that they will recompute already known data.
    # some internal refactoring could probably make this avoid needless
    # extra calculations.
    scriptVersion = 0
    if scriptClass == ScriptHashTy:
        # Nothing to merge if either the new or previous signature
        # scripts are empty or fail to parse.

        if (
            len(sigScript) == 0
            or checkScriptParses(scriptVersion, sigScript) is not None
        ):
            return prevScript
        if (
            not prevScript
            or len(prevScript) == 0
            or checkScriptParses(scriptVersion, prevScript) is not None
        ):
            return sigScript

        # Remove the last push in the script and then recurse.
        # this could be a lot less inefficient.
        #
        # Assume that final script is the correct one since it was just
        # made and it is a pay-to-script-hash.
        script = finalOpcodeData(scriptVersion, sigScript)

        # We already know this information somewhere up the stack,
        # therefore the error is ignored.
        scriptClass, addresses, nrequired = extractPkScriptAddrs(
            DefaultScriptVersion, script, netParams
        )

        # Merge
        mergedScript = mergeScripts(
            netParams,
            tx,
            idx,
            script,
            scriptClass,
            addresses,
            nrequired,
            sigScript,
            prevScript,
        )

        # Reappend the script and return the result.
        finalScript = ByteArray(b"", length=0)
        finalScript += mergedScript
        finalScript += addData(script)
        return finalScript
    elif scriptClass == MultiSigTy:
        return mergeMultiSig(
            tx, idx, addresses, nRequired, pkScript, sigScript, prevScript
        )
    else:
        # It doesn't actually make sense to merge anything other than multisig
        # and scripthash (because it could contain multisig). Everything else
        # has either zero signatures, can't be spent, or has a single signature
        # which is either present or not. The other two cases are handled
        # above. In the conflicting case here we just assume the longest is
        # correct (this matches behaviour of the reference implementation).
        if prevScript is None or len(sigScript) > len(prevScript):
            return sigScript
        return prevScript


def mergeMultiSig(tx, idx, addresses, nRequired, pkScript, sigScript, prevScript):
    """
    mergeMultiSig combines the two signature scripts sigScript and prevScript
    that both provide signatures for pkScript in output idx of tx. addresses
    and nRequired should be the results from extracting the addresses from
    pkScript. Since this function is internal only we assume that the arguments
    have come from other functions internally and thus are all consistent with
    each other, behaviour is undefined if this contract is broken.

    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.

    Args:
        tx (object): the ticket purchase MsgTx.
        idx (int): the output index that contains the multisig.
        addresses (object): the addresses that make up the multisig.
        nRequired (int): the number of signatures required to fulfill the pkScript.
        pkScript (byte-like): the multisig script.
        sigScript (byte-like): the mulitsig script's signature.
        prevScript (byte-like): the output's previous signature script.

    Returns:
        byte-like: the merged signature scripts.
    """

    # Nothing to merge if either the new or previous signature scripts are
    # empty.
    if not sigScript or len(sigScript) == 0:
        return prevScript

    if not prevScript or len(prevScript) == 0:
        return sigScript

    # Convenience function to avoid duplication.
    possibleSigs = []

    def extractSigs(script):
        found = False
        scriptVersion = 0
        tokenizer = ScriptTokenizer(scriptVersion, script)
        while tokenizer.next():
            data = tokenizer.data()
            if len(data) != 0:
                found = True
                possibleSigs.append(data)
        if tokenizer.err is not None:
            raise DecredError("mergeMultiSig: extractSigs: {}".format(tokenizer.err))
        return found

    # Attempt to extract signatures from the two scripts.  Return the other
    # script that is intended to be merged in the case signature extraction
    # fails for some reason.
    if not extractSigs(sigScript):
        return prevScript

    if not extractSigs(prevScript):
        return sigScript

    # Now we need to match the signatures to pubkeys, the only real way to
    # do that is to try to verify them all and match it to the pubkey
    # that verifies it. we then can go through the addresses in order
    # to build our script. Anything that doesn't parse or doesn't verify we
    # throw away.
    addrToSig = {}
    for sig in possibleSigs:

        # can't have a valid signature that doesn't at least have a
        # hashtype, in practise it is even longer than this. but
        # that'll be checked next.
        if len(sig) < 1:
            continue
        tSig = sig[:-1]
        hashType = sig[-1]

        try:
            pSig = Signature.parse(tSig, True)
        except DecredError:
            continue

        # We have to do this each round since hash types may vary
        # between signatures and so the hash will vary. We can,
        # however, assume no sigs etc are in the script since that
        # would make the transaction nonstandard and thus not
        # MultiSigTy, so we just need to hash the full thing.
        sigHash = calcSignatureHash(pkScript, hashType, tx, idx, None)

        for addr in addresses:
            # All multisig addresses should be pubkey addresses
            # it is an error to call this internal function with
            # bad input.

            # If it matches we put it in the map. We only
            # can take one signature per public key so if we
            # already have one, we can throw this away.
            if verifySig(addr.pubkey, sigHash, pSig.r.int(), pSig.s.int()):
                addrToSig[addr.string()] = sig

    script = ByteArray(b"")
    doneSigs = 0
    # This assumes that addresses are in the same order as in the script.
    for addr in addresses:
        a = addr.string()
        if a in addrToSig:
            script += addData(addrToSig[a])
            doneSigs += 1
        if doneSigs == nRequired:
            break

    # padding for missing ones
    for i in range(nRequired - doneSigs):
        script += opcode.OP_0

    return script


def signTxOutput(
    netParams, tx, idx, pkScript, hashType, keysource, previousScript, sigType
):
    """
    signTxOutput signs output idx of the given tx to resolve the script given in
    pkScript with a signature type of hashType. Any keys required will be
    looked up by calling getKey() with the string of the given address.
    Any pay-to-script-hash signatures will be similarly looked up by calling
    getScript. If previousScript is provided then the results in previousScript
    will be merged in a type-dependent manner with the newly generated.
    signature script.

    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """

    sigScript, scriptClass, addresses, nrequired = sign(
        netParams, tx, idx, pkScript, hashType, keysource, sigType
    )

    isStakeType = (
        scriptClass == StakeSubmissionTy
        or scriptClass == StakeSubChangeTy
        or scriptClass == StakeGenTy
        or scriptClass == StakeRevocationTy
    )
    if isStakeType:
        scriptClass = getStakeOutSubclass(pkScript)

    if scriptClass == ScriptHashTy:
        raise NotImplementedError("ScriptHashTy signing unimplemented")
        # # TODO keep the sub addressed and pass down to merge.
        # realSigScript, _, _, _ = sign(
        #     privKey, netParams, tx, idx, sigScript, hashType, sigType)

        # Append the p2sh script as the last push in the script.
        # script = ByteArray(b'')
        # script += realSigScript
        # script += addData(sigScript)

        # sigScript = script
        # # TODO keep a copy of the script for merging.

    # Merge scripts. with any previous data, if any.
    mergedScript = mergeScripts(
        netParams,
        tx,
        idx,
        pkScript,
        scriptClass,
        addresses,
        nrequired,
        sigScript,
        previousScript,
    )
    return mergedScript


def getP2PKHOpCode(pkScript):
    """
    getP2PKHOpCode returns opNonstake for non-stake transactions, or
    the stake op code tag for stake transactions.

    Args:
        pkScript (ByteArray): The pubkey script.

    Returns:
        int: The opcode tag for the script types parsed from the script.
    """
    scriptClass = getScriptClass(DefaultScriptVersion, pkScript)
    if scriptClass == NonStandardTy:
        raise NotImplementedError("unknown script class")
    if scriptClass == StakeSubmissionTy:
        return opcode.OP_SSTX
    elif scriptClass == StakeGenTy:
        return opcode.OP_SSGEN
    elif scriptClass == StakeRevocationTy:
        return opcode.OP_SSRTX
    elif scriptClass == StakeSubChangeTy:
        return opcode.OP_SSTXCHANGE
    return opNonstake


def spendScriptSize(pkScript):
    """
    Get the byte-length of the spend script.

    Args:
        pkScript (ByteArray): The pubkey script.

    Returns:
        int: Byte-length of script.
    """
    # Unspent credits are currently expected to be either P2PKH or
    # P2PK, P2PKH/P2SH nested in a revocation/stakechange/vote output.
    scriptClass = getScriptClass(DefaultScriptVersion, pkScript)
    if scriptClass == PubKeyHashTy:
        return RedeemP2PKHSigScriptSize
    elif scriptClass == PubKeyTy:
        return RedeemP2PKSigScriptSize
    elif scriptClass in (StakeRevocationTy, StakeSubChangeTy, StakeGenTy):
        scriptClass = getStakeOutSubclass(pkScript)
        # For stake transactions we expect P2PKH and P2SH script class
        # types only but ignore P2SH script type since it can pay
        # to any script which the wallet may not recognize.
        if scriptClass != PubKeyHashTy:
            raise DecredError(
                "unexpected nested script class for credit: %d" % scriptClass
            )
        return RedeemP2PKHSigScriptSize
    raise NotImplementedError("unimplemented: %s : %r" % (scriptClass, scriptClass))


def estimateInputSize(scriptSize):
    """
    estimateInputSize returns the worst case serialize size estimate for a tx input
      - 32 bytes previous tx
      - 4 bytes output index
      - 1 byte tree
      - 8 bytes amount
      - 4 bytes block height
      - 4 bytes block index
      - the compact int representation of the script size
      - the supplied script size
      - 4 bytes sequence

    Args:
        scriptSize int: Byte-length of the script.

    Returns:
        int: Estimated size of the byte-encoded transaction input.
    """
    return (
        32 + 4 + 1 + 8 + 4 + 4 + wire.varIntSerializeSize(scriptSize) + scriptSize + 4
    )


def estimateOutputSize(scriptSize):
    """
    estimateOutputSize returns the worst case serialize size estimate for a tx output
      - 8 bytes amount
      - 2 bytes version
      - the compact int representation of the script size
      - the supplied script size

    Args:
        scriptSize int: Byte-length of the script.

    Returns:
        int: Estimated size of the byte-encoded transaction output.
    """
    return 8 + 2 + wire.varIntSerializeSize(scriptSize) + scriptSize


def sumOutputSerializeSizes(outputs):  # outputs []*wire.TxOut) (serializeSize int) {
    """
    sumOutputSerializeSizes sums up the serialized size of the supplied outputs.

    Args:
        outputs list(TxOut): Transaction outputs.

    Returns:
        int: Estimated size of the byte-encoded transaction outputs.
    """
    serializeSize = 0
    for txOut in outputs:
        serializeSize += txOut.serializeSize()
    return serializeSize


def estimateSerializeSize(scriptSizes, txOuts, changeScriptSize):
    """
    estimateSerializeSize returns a worst case serialize size estimate for a
    signed transaction that spends a number of outputs and contains each
    transaction output from txOuts. The estimated size is incremented for an
    additional change output if changeScriptSize is greater than 0. Passing 0
    does not add a change output.

    Args:
        scriptSizes list(int): Pubkey script sizes
        txOuts list(TxOut): Transaction outputs.
        changeScriptSize int: Size of the change script.

    Returns:
        int: Estimated size of the byte-encoded transaction outputs.
    """
    # Generate and sum up the estimated sizes of the inputs.
    txInsSize = 0
    for size in scriptSizes:
        txInsSize += estimateInputSize(size)

    inputCount = len(scriptSizes)
    outputCount = len(txOuts)
    changeSize = 0
    if changeScriptSize > 0:
        changeSize = estimateOutputSize(changeScriptSize)
        outputCount += 1
    # 12 additional bytes are for version, locktime and expiry.
    return (
        12
        + (2 * wire.varIntSerializeSize(inputCount))
        + wire.varIntSerializeSize(outputCount)
        + txInsSize
        + sumOutputSerializeSizes(txOuts)
        + changeSize
    )


def calcMinRequiredTxRelayFee(relayFeePerKb, txSerializeSize):
    """
    calcMinRequiredTxRelayFee returns the minimum transaction fee required for a
    transaction with the passed serialized size to be accepted into the memory
    pool and relayed.

    Args:
        relayFeePerKb (float): The fee per kilobyte.
        txSerializeSize int: (Size) of the byte-encoded transaction.

    Returns:
        int: Fee in atoms.
    """
    # Calculate the minimum fee for a transaction to be allowed into the
    # mempool and relayed by scaling the base fee (which is the minimum
    # free transaction relay fee).  minTxRelayFee is in Atom/KB, so
    # multiply by serializedSize (which is in bytes) and divide by 1000 to
    # get minimum Atoms.
    fee = relayFeePerKb * txSerializeSize // 1000

    if fee == 0 and relayFeePerKb > 0:
        fee = relayFeePerKb

    if fee < 0 or fee > MaxAmount:  # dcrutil.MaxAmount:
        fee = MaxAmount
    return round(fee)


def isDustAmount(amount, scriptSize, relayFeePerKb):
    """
    isDustAmount determines whether a transaction output value and script length
    would cause the output to be considered dust.  Transactions with dust outputs
    are not standard and are rejected by mempools with default policies.

    Args:
        amount (int): Atoms.
        scriptSize (int): Byte-size of the script.
        relayFeePerKb (float): Fees paid per kilobyte.

    Returns:
        bool: True if the amount is considered dust.
    """
    # Calculate the total (estimated) cost to the network.  This is
    # calculated using the serialize size of the output plus the serial
    # size of a transaction input which redeems it.  The output is assumed
    # to be compressed P2PKH as this is the most common script type.  Use
    # the average size of a compressed P2PKH redeem input (165) rather than
    # the largest possible (txsizes.RedeemP2PKHInputSize).
    totalSize = 8 + 2 + wire.varIntSerializeSize(scriptSize) + scriptSize + 165

    # Dust is defined as an output value where the total cost to the network
    # (output size + input size) is greater than 1/3 of the relay fee.
    return amount * 1000 / (3 * totalSize) < relayFeePerKb


def isUnspendable(amount, pkScript):
    """
    isUnspendable returns whether the passed public key script is unspendable, or
    guaranteed to fail at execution.  This allows inputs to be pruned instantly
    when entering the UTXO set. In Decred, all zero value outputs are unspendable.

    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.

    Args:
        amount (int): Value of the txOut the script spends.
        pkScript (ByteArray): The pubkey script.

    Returns:
        bool: True is script unspendable.
    """
    # The script is unspendable if amount is zero, it starts with OP_RETURN or
    # is guaranteed to fail at execution due to being larger than the max
    # allowed script size.
    if (
        amount == 0
        or len(pkScript) > MaxScriptSize
        or len(pkScript) > 0
        and pkScript[0] == opcode.OP_RETURN
    ):
        return True

    # The script is unspendable if it is guaranteed to fail at execution.
    scriptVersion = 0
    return checkScriptParses(scriptVersion, pkScript) is not None


def isDustOutput(output, relayFeePerKb):
    """
    isDustOutput determines whether a transaction output is considered dust.
    Transactions with dust outputs are not standard and are rejected by mempools
    with default policies.

    Args:
        output (wire.TxOut): The transaction output.
        relayFeePerKb: Minimum transaction fee allowable.

    Returns:
        bool: True if output is a dust output.
    """
    # Unspendable outputs which solely carry data are not checked for dust.
    if getScriptClass(output.version, output.pkScript) == NullDataTy:
        return False

    # All other unspendable outputs are considered dust.
    if isUnspendable(output.value, output.pkScript):
        return True

    return isDustAmount(output.value, len(output.pkScript), relayFeePerKb)


def estimateSerializeSizeFromScriptSizes(inputSizes, outputSizes, changeScriptSize):
    """
    estimateSerializeSizeFromScriptSizes returns a worst case serialize size
    estimate for a signed transaction that spends len(inputSizes) previous
    outputs and pays to len(outputSizes) outputs with scripts of the provided
    worst-case sizes. The estimated size is incremented for an additional
    change output if changeScriptSize is greater than 0. Passing 0 does not
    add a change output.

    Args:
        intputSizes (list(int)): The sizes of the input scripts.
        outputSizes (list(int)): The sizes of the output scripts.
        changeScriptSize (int): The size of the change script.

    Returns:
        int: The estimated serialized transaction size.
    """
    # Generate and sum up the estimated sizes of the inputs.
    txInsSize = 0
    for inputSize in inputSizes:
        txInsSize += estimateInputSize(inputSize)

    # Generate and sum up the estimated sizes of the outputs.
    txOutsSize = 0
    for outputSize in outputSizes:
        txOutsSize += estimateOutputSize(outputSize)

    inputCount = len(inputSizes)
    outputCount = len(outputSizes)
    changeSize = 0
    if changeScriptSize > 0:
        changeSize = estimateOutputSize(changeScriptSize)
        outputCount += 1

    # 12 additional bytes are for version, locktime and expiry.
    return (
        12
        + (2 * varIntSerializeSize(inputCount))
        + varIntSerializeSize(outputCount)
        + txInsSize
        + txOutsSize
        + changeSize
    )


class SubsidyCache:
    """
    SubsidyCache provides efficient access to consensus-critical subsidy
    calculations for blocks and votes, including the max potential subsidy for
    given block heights, the proportional proof-of-work subsidy, the proportional
    proof of stake per-vote subsidy, and the proportional treasury subsidy.

    It makes use of caching to avoid repeated calculations.
    """

    def __init__(self, netParams):
        """
        Args:
            netParams (module): The network parameters.
        """
        # netParams stores the subsidy parameters to use during subsidy
        # calculation.
        self.netParams = netParams

        # cache houses the cached subsidies keyed by reduction interval.
        self.cache = {0: netParams.BaseSubsidy}

        # cachedIntervals contains an ordered list of all cached intervals.
        # It is used to efficiently track sparsely cached intervals with
        # O(log N) discovery of a prior cached interval.
        self.cachedIntervals = [0]

        # These fields house values calculated from the parameters in order to
        # avoid repeated calculation.
        #
        # minVotesRequired is the minimum number of votes required for a block to
        # be consider valid by consensus.
        #
        # totalProportions is the sum of the PoW, PoS, and Treasury proportions.
        self.minVotesRequired = (netParams.TicketsPerBlock // 2) + 1
        self.totalProportions = (
            netParams.WorkRewardProportion
            + netParams.StakeRewardProportion
            + netParams.BlockTaxProportion
        )

    def calcBlockSubsidy(self, height):
        """
        calcBlockSubsidy returns the max potential subsidy for a block at the
        provided height.  This value is reduced over time based on the height and
        then split proportionally between PoW, PoS, and the Treasury.
        """
        # Negative block heights are invalid and produce no subsidy.
        # Block 0 is the genesis block and produces no subsidy.
        # Block 1 subsidy is special as it is used for initial token distribution.
        if height <= 0:
            return 0
        elif height == 1:
            return self.netParams.BlockOneSubsidy

        # Calculate the reduction interval associated with the requested height and
        # attempt to look it up in cache.  When it's not in the cache, look up the
        # latest cached interval and subsidy.
        reqInterval = height // self.netParams.SubsidyReductionInterval
        if reqInterval in self.cache:
            return self.cache[reqInterval]

        lastCachedInterval = self.cachedIntervals[len(self.cachedIntervals) - 1]
        lastCachedSubsidy = self.cache[lastCachedInterval]

        # When the requested interval is after the latest cached interval, avoid
        # additional work by either determining if the subsidy is already exhausted
        # at that interval or using the interval as a starting point to calculate
        # and store the subsidy for the requested interval.
        #
        # Otherwise, the requested interval is prior to the final cached interval,
        # so use a binary search to find the latest cached interval prior to the
        # requested one and use it as a starting point to calculate and store the
        # subsidy for the requested interval.
        if reqInterval > lastCachedInterval:
            # Return zero for all intervals after the subsidy reaches zero.  This
            # enforces an upper bound on the number of entries in the cache.
            if lastCachedSubsidy == 0:
                return 0
        else:
            cachedIdx = bisect.bisect_left(self.cachedIntervals, reqInterval)
            lastCachedInterval = self.cachedIntervals[cachedIdx - 1]
            lastCachedSubsidy = self.cache[lastCachedInterval]

        # Finally, calculate the subsidy by applying the appropriate number of
        # reductions per the starting and requested interval.
        reductionMultiplier = self.netParams.MulSubsidy
        reductionDivisor = self.netParams.DivSubsidy
        subsidy = lastCachedSubsidy
        neededIntervals = reqInterval - lastCachedInterval
        for i in range(neededIntervals):
            subsidy *= reductionMultiplier
            subsidy = subsidy // reductionDivisor

            # Stop once no further reduction is possible.  This ensures a bounded
            # computation for large requested intervals and that all future
            # requests for intervals at or after the final reduction interval
            # return 0 without recalculating.
            if subsidy == 0:
                reqInterval = lastCachedInterval + i + 1
                break

        # Update the cache for the requested interval or the interval in which the
        # subsidy became zero when applicable.  The cached intervals are stored in
        # a map for O(1) lookup and also tracked via a sorted array to support the
        # binary searches for efficient sparse interval query support.
        self.cache[reqInterval] = subsidy

        bisect.insort_left(self.cachedIntervals, reqInterval)
        return subsidy

    def calcWorkSubsidy(self, height, voters):
        # The first block has special subsidy rules.
        if height == 1:
            return self.netParams.BlockOneSubsidy

        # The subsidy is zero if there are not enough voters once voting begins.  A
        # block without enough voters will fail to validate anyway.
        stakeValidationHeight = self.netParams.StakeValidationHeight
        if height >= stakeValidationHeight and voters < self.minVotesRequired:
            return 0

        # Calculate the full block subsidy and reduce it according to the PoW
        # proportion.
        subsidy = self.calcBlockSubsidy(height)
        subsidy *= self.netParams.WorkRewardProportion
        subsidy = subsidy // self.totalProportions

        # Ignore any potential subsidy reductions due to the number of votes prior
        # to the point voting begins.
        if height < stakeValidationHeight:
            return subsidy

        # Adjust for the number of voters.
        return (voters * subsidy) // self.netParams.TicketsPerBlock

    def calcStakeVoteSubsidy(self, height):
        """
        CalcStakeVoteSubsidy returns the subsidy for a single stake vote for a block.
        It is calculated as a proportion of the total subsidy and max potential
        number of votes per block.

        Unlike the Proof-of-Work and Treasury subsidies, the subsidy that votes
        receive is not reduced when a block contains less than the maximum number of
        votes.  Consequently, this does not accept the number of votes.  However, it
        is important to note that blocks that do not receive the minimum required
        number of votes for a block to be valid by consensus won't actually produce
        any vote subsidy either since they are invalid.

        This function is safe for concurrent access.
        """
        # Votes have no subsidy prior to the point voting begins.  The minus one
        # accounts for the fact that vote subsidy are, unfortunately, based on the
        # height that is being voted on as opposed to the block in which they are
        # included.
        if height < self.netParams.StakeValidationHeight - 1:
            return 0

        # Calculate the full block subsidy and reduce it according to the stake
        # proportion.  Then divide it by the number of votes per block to arrive
        # at the amount per vote.
        subsidy = self.calcBlockSubsidy(height)
        proportions = self.totalProportions
        subsidy *= self.netParams.StakeRewardProportion
        subsidy = subsidy // (proportions * self.netParams.TicketsPerBlock)

        return subsidy

    def calcTreasurySubsidy(self, height, voters):
        """
        calcTreasurySubsidy returns the subsidy required to go to the treasury for
        a block.  It is calculated as a proportion of the total subsidy and further
        reduced proportionally depending on the number of votes once the height at
        which voting begins has been reached.

        Note that passing a number of voters fewer than the minimum required for a
        block to be valid by consensus along with a height greater than or equal to
        the height at which voting begins will return zero.

        This function is safe for concurrent access.
        """
        # The first two blocks have special subsidy rules.
        if height <= 1:
            return 0

        # The subsidy is zero if there are not enough voters once voting begins.  A
        # block without enough voters will fail to validate anyway.
        stakeValidationHeight = self.netParams.StakeValidationHeight
        if height >= stakeValidationHeight and voters < self.minVotesRequired:
            return 0

        # Calculate the full block subsidy and reduce it according to the treasury
        # proportion.
        subsidy = self.calcBlockSubsidy(height)
        subsidy *= self.netParams.BlockTaxProportion
        subsidy = subsidy // self.totalProportions

        # Ignore any potential subsidy reductions due to the number of votes prior
        # to the point voting begins.
        if height < stakeValidationHeight:
            return subsidy

        # Adjust for the number of voters.
        return (voters * subsidy) // self.netParams.TicketsPerBlock


def stakePoolTicketFee(stakeDiff, relayFee, height, poolFee, subsidyCache, netParams):
    """
    stakePoolTicketFee determines the stake pool ticket fee for a given ticket
    from the passed percentage. Pool fee as a percentage is truncated from 0.01%
    to 100.00%. This all must be done with integers.

    Args:
        stakeDiff (int): The ticket price.
        relayFee (int): Transaction fees.
        height (int): Current block height.
        poolFee (int): The pools fee, as percent.
        subsidyCache (calc.SubsidyCache): A subsidy cache.
        netParams (module): The network parameters.

    Returns:
        int: The stake pool ticket fee.

    """
    # Shift the decimal two places, e.g. 1.00%
    # to 100. This assumes that the proportion
    # is already multiplied by 100 to give a
    # percentage, thus making the entirety
    # be a multiplication by 10000.
    poolFeeAbs = math.floor(poolFee * 100.0)
    poolFeeInt = int(poolFeeAbs)

    # Subsidy is fetched from the blockchain package, then
    # pushed forward a number of adjustment periods for
    # compensation in gradual subsidy decay. Recall that
    # the average time to claiming 50% of the tickets as
    # votes is the approximately the same as the ticket
    # pool size (netParams.TicketPoolSize), so take the
    # ceiling of the ticket pool size divided by the
    # reduction interval.
    adjs = int(math.ceil(netParams.TicketPoolSize / netParams.SubsidyReductionInterval))
    subsidy = subsidyCache.calcStakeVoteSubsidy(height)
    for i in range(adjs):
        subsidy *= 100
        subsidy = subsidy // 101

    # The numerator is (p*10000*s*(v+z)) << 64.
    shift = 64
    s = subsidy
    v = int(stakeDiff)
    z = int(relayFee)
    num = poolFeeInt
    num *= s
    vPlusZ = v + z
    num *= vPlusZ
    num = num << shift

    # The denominator is 10000*(s+v).
    # The extra 10000 above cancels out.
    den = s
    den += v
    den *= 10000

    # Divide and shift back.
    num = num // den
    num = num >> shift

    return num


def sstxNullOutputAmounts(amounts, changeAmounts, amountTicket):
    """
    sstxNullOutputAmounts takes an array of input amounts, change amounts, and a
    ticket purchase amount, calculates the adjusted proportion from the purchase
    amount, stores it in an array, then returns the array.  That is, for any
    given SStx, this function calculates the proportional outputs that any
    single user should receive.

    Args:
        amounts (list(int)): Input values.
        changeAmounts (list(int)): The change output values.
        amountTicket: Ticket price.

    Returns:
        int: Ticket fees.
        list(int): Adjusted output amounts.
    """
    lengthAmounts = len(amounts)

    if lengthAmounts != len(changeAmounts):
        raise DecredError("amounts was not equal in length to change amounts!")

    if amountTicket <= 0:
        raise DecredError("committed amount was too small!")

    contribAmounts = []
    total = 0

    # Now we want to get the adjusted amounts.  The algorithm is like this:
    # 1 foreach amount
    # 2     subtract change from input, store
    # 3     add this amount to total
    # 4 check total against the total committed amount
    for i in range(lengthAmounts):
        contrib = amounts[i] - changeAmounts[i]
        if contrib < 0:
            raise DecredError(
                "change at idx %d spent more coins than allowed (have: %r, spent: %r)"
                % (i, amounts[i], changeAmounts[i])
            )
        total += contrib
        contribAmounts.append(contrib)

    fees = total - amountTicket

    return fees, contribAmounts


def makeTicket(
    netParams,
    inputPool,
    inputMain,
    addrVote,
    addrSubsidy,
    ticketCost,
    addrPool,
    limits=defaultTicketFeeLimits,
):
    """
    makeTicket creates a ticket from a split transaction output. It can optionally
    create a ticket that pays a fee to a pool if a pool input and pool address are
    passed.

    Args:
        netParams (module): The network parameters.
        inputPool (ExtendedOutPoint): The pool input's extended outpoint.
        inputMain (ExtendedOutPoint): The wallet input's extended outpoint.
        addrVote (Address): The voting address.
        addrSubsidy (Address): Wallet's stake commitment address.
        ticketCost (int): The ticket price.
        addrPool (Address): The pool's commitment address.
        limits (int): Fee limits to invoke on the spending tx.

    Returns:
        wire.MsgTx: The ticket.
    """

    mtx = msgtx.MsgTx.new()

    if not addrPool or not inputPool:
        raise NotImplementedError("solo tickets not supported")

    if not addrVote:
        raise DecredError("no voting address provided")

    txIn = msgtx.TxIn(previousOutPoint=inputPool.op, valueIn=inputPool.amt)
    mtx.addTxIn(txIn)

    txIn = msgtx.TxIn(previousOutPoint=inputMain.op, valueIn=inputMain.amt)
    mtx.addTxIn(txIn)

    # Create a new script which pays to the provided address with an
    # SStx tagged output.
    pkScript = payToSStx(addrVote)

    txOut = msgtx.TxOut(value=ticketCost, pkScript=pkScript,)
    mtx.addTxOut(txOut)

    # Obtain the commitment amounts.
    _, amountsCommitted = sstxNullOutputAmounts(
        [inputPool.amt, inputMain.amt], [0, 0], ticketCost
    )
    userSubsidyNullIdx = 1

    # Zero value P2PKH addr.
    zeroed = ByteArray(b"", length=20)
    addrZeroed = addrlib.AddressPubKeyHash(zeroed, netParams, crypto.STEcdsaSecp256k1)

    # 2. Make an extra commitment to the pool.
    pkScript = generateSStxAddrPush(addrPool, amountsCommitted[0], limits)
    txout = msgtx.TxOut(value=0, pkScript=pkScript,)
    mtx.addTxOut(txout)

    # Create a new script which pays to the provided address with an
    # SStx change tagged output.
    pkScript = payToSStxChange(addrZeroed)

    txOut = msgtx.TxOut(value=0, pkScript=pkScript,)
    mtx.addTxOut(txOut)

    # 3. Create the commitment and change output paying to the user.
    #
    # Create an OP_RETURN push containing the pubkeyhash to send rewards to.
    # Apply limits to revocations for fees while not allowing
    # fees for votes.
    pkScript = generateSStxAddrPush(
        addrSubsidy, amountsCommitted[userSubsidyNullIdx], limits
    )
    txout = msgtx.TxOut(value=0, pkScript=pkScript,)
    mtx.addTxOut(txout)

    # Create a new script which pays to the provided address with an
    # SStx change tagged output.
    pkScript = payToSStxChange(addrZeroed)
    txOut = msgtx.TxOut(value=0, pkScript=pkScript,)
    mtx.addTxOut(txOut)

    # Make sure we generated a valid SStx.
    checkSStx(mtx)

    return mtx


def sstxStakeOutputInfo(outs):
    """
    sstxStakeOutputInfo takes a list of msgtx.txOut as input and scans through
    its outputs, returning the pubkeyhashs and amounts for any NullDataTy's
    (future commitments to stake generation rewards).

    Args:
        outs (list(object)): an SStx MsgTx outputs

    Returns:
        list(bool): is pay-to-script-hash.
        list(byte-like): the output addresses.
        list(int): the subsidy amounts.
        list(int): the change amounts.
        list(list(bool)): the spend rules.
        list(list(int)): the spend limits.
    """
    isP2SH = []
    addresses = []
    amounts = []
    changeAmounts = []
    allSpendRules = []
    allSpendLimits = []

    # Cycle through the inputs and pull the proportional amounts
    # and commit to PKHs/SHs.
    for idx in range(len(outs)):
        # We only care about the outputs where we get proportional
        # amounts and the PKHs/SHs to send rewards to, which is all
        # the odd numbered output indexes.
        if (idx > 0) and (idx % 2 != 0):
            # The MSB (sign), not used ever normally, encodes whether
            # or not it is a P2PKH or P2SH for the input.
            amtEncoded = outs[idx].pkScript[22:30]
            # MSB set?
            isP2SH.append(not (amtEncoded[7] & (1 << 7) == 0))
            # Clear bit
            amtEncoded[7] &= 127

            addresses.append(outs[idx].pkScript[2:22])
            # amounts[idx/2] = int64(binary.LittleEndian.Uint64(amtEncoded))
            amounts.append(ByteArray(amtEncoded, length=8).littleEndian().int())

            # Get flags and restrictions for the outputs to be
            # made in either a vote or revocation.
            spendRules = []
            spendLimits = []

            # This bitflag is true/false.
            feeLimitUint16 = (
                ByteArray(outs[idx].pkScript[30:32], length=4).littleEndian().int()
            )
            spendRules.append(
                (feeLimitUint16 & SStxVoteFractionFlag) == SStxVoteFractionFlag
            )
            spendRules.append(
                (feeLimitUint16 & SStxRevFractionFlag) == SStxRevFractionFlag
            )
            allSpendRules.append(spendRules)

            # This is the fraction to use out of 64.
            spendLimits.append(feeLimitUint16 & SStxVoteReturnFractionMask)
            spendLimits.append(feeLimitUint16 & SStxRevReturnFractionMask)
            spendLimits[1] >>= 8
            allSpendLimits.append(spendLimits)

        # Here we only care about the change amounts, so scan
        # the change outputs (even indices) and save their
        # amounts.
        if (idx > 0) and (idx % 2 == 0):
            changeAmounts.append(outs[idx].value)

    return isP2SH, addresses, amounts, changeAmounts, allSpendRules, allSpendLimits


def calculateRewards(amounts, amountTicket, subsidy):
    """
    calculateRewards takes a list of SStx adjusted output amounts, the amount used
    to purchase that ticket, and the reward for an SSGen tx and subsequently
    generates what the outputs should be in the SSGen tx.  If used for calculating
    the outputs for an SSRtx, pass 0 for subsidy.

    Args:
        amounts list (int): output amounts.
        amountTicket (int): amount used to purchase ticket.
        subsidy (int): amount to pay.

    Returns:
        list(int): list of SStx adjusted output amounts.
    """
    outputsAmounts = []

    # SSGen handling
    amountWithStakebase = amountTicket + subsidy

    # Get the sum of the amounts contributed between both fees
    # and contributions to the ticket.
    totalContrib = 0
    for amount in amounts:
        totalContrib += amount

    # Now we want to get the adjusted amounts including the reward.
    # The algorithm is like this:
    # 1 foreach amount
    # 2     amount *= 2^32
    # 3     amount /= amountTicket
    # 4     amount *= amountWithStakebase
    # 5     amount /= 2^32

    for amount in amounts:
        # mul amountWithStakebase
        amount *= amountWithStakebase

        # mul 2^32
        amount <<= 32

        # div totalContrib
        amount //= totalContrib

        # div 2^32
        amount >>= 32

        # make int64
        outputsAmounts.append(amount)

    return outputsAmounts


def makeRevocation(ticketPurchase, feePerKB):
    """
    makeRevocation creates an unsigned revocation transaction that
    revokes a missed or expired ticket.  Revocations must carry a relay fee and
    this function can error if the revocation contains no suitable output to
    decrease the estimated relay fee from.

    Args:
        ticketPurchase (object): the ticket to revoke's MsgTx.
        feePerKB (int): the miner's fee per kb.

    Returns:
        object: the unsigned revocation MsgTx or None in case of error.
    """
    # Parse the ticket purchase transaction to determine the required output
    # destinations for vote rewards or revocations.
    ticketPayKinds, ticketHash160s, ticketValues, _, _, _ = sstxStakeOutputInfo(
        ticketPurchase.txOut
    )

    # Calculate the output values for the revocation.  Revocations do not
    # contain any subsidy.
    revocationValues = calculateRewards(ticketValues, ticketPurchase.txOut[0].value, 0)

    # Begin constructing the revocation transaction.
    revocation = msgtx.MsgTx.new()

    # Revocations reference the ticket purchase with the first (and only)
    # input.
    ticketOutPoint = msgtx.OutPoint(ticketPurchase.hash(), 0, msgtx.TxTreeStake)
    ticketInput = msgtx.TxIn(
        previousOutPoint=ticketOutPoint,
        valueIn=ticketPurchase.txOut[ticketOutPoint.index].value,
    )
    revocation.addTxIn(ticketInput)
    scriptSizes = [RedeemP2SHSigScriptSize]

    # All remaining outputs pay to the output destinations and amounts tagged
    # by the ticket purchase.
    for i in range(len(ticketHash160s)):
        scriptFn = payToStakePKHScript
        # P2SH
        if ticketPayKinds[i]:
            scriptFn = payToStakeSHScript
        script = scriptFn(ticketHash160s[i], opcode.OP_SSRTX)
        revocation.addTxOut(msgtx.TxOut(revocationValues[i], script))

    # Revocations must pay a fee but do so by decreasing one of the output
    # values instead of increasing the input value and using a change output.
    # Calculate the estimated signed serialize size.
    sizeEstimate = estimateSerializeSize(scriptSizes, revocation.txOut, 0)
    feeEstimate = calcMinRequiredTxRelayFee(feePerKB, sizeEstimate)

    # Reduce the output value of one of the outputs to accommodate for the relay
    # fee. To avoid creating dust outputs, a suitable output value is reduced
    # by the fee estimate only if it is large enough to not create dust. This
    # code does not currently handle reducing the output values of multiple
    # commitment outputs to accommodate for the fee.
    for output in revocation.txOut:
        if output.value > feeEstimate:
            amount = output.value - feeEstimate
            if not isDustAmount(amount, len(output.pkScript), feePerKB):
                output.value = amount
                return revocation
    raise DecredError("missing suitable revocation output to pay relay fee")
