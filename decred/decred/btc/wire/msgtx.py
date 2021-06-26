import hashlib
from typing import List, Union, Optional

from decred import DecredError
from decred.util.encode import ByteArray
from decred.btc.wire import wire
from decred.dcr.wire import wire as dcrwire

# chainhash.HashSize in Go
HASH_SIZE = 32

# TxVersion is the current latest supported transaction version.
TxVersion = 1

# MaxTxInSequenceNum is the maximum sequence number the sequence field
# of a transaction input can be.
MaxTxInSequenceNum = 0xffffffff

# MaxPrevOutIndex is the maximum index the index field of a previous
# outpoint can be.
MaxPrevOutIndex = 0xffffffff

# SequenceLockTimeDisabled is a flag that if set on a transaction
# input's sequence number, the sequence number will not be interpreted
# as a relative locktime.
SequenceLockTimeDisabled = 1 << 31

# SequenceLockTimeIsSeconds is a flag that if set on a transaction
# input's sequence number, the relative locktime has units of 512
# seconds.
SequenceLockTimeIsSeconds = 1 << 22

# SequenceLockTimeMask is a mask that extracts the relative locktime
# when masked against the transaction input sequence number.
SequenceLockTimeMask = 0x0000ffff

# SequenceLockTimeGranularity is the defined time based granularity
# for seconds-based relative time locks. When converting from seconds
# to a sequence number, the value is right shifted by this amount,
# therefore the granularity of relative time locks in 512 or 2^9
# seconds. Enforced relative lock times are multiples of 512 seconds.
SequenceLockTimeGranularity = 9

# defaultTxInOutAlloc is the default size used for the backing array for
# transaction inputs and outputs.  The array will dynamically grow as needed,
# but this figure is intended to provide enough space for the number of
# inputs and outputs in a typical transaction without needing to grow the
# backing array multiple times.
defaultTxInOutAlloc = 15

# minTxInPayload is the minimum payload size for a transaction input.
# PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Varint for
# SignatureScript length 1 byte + Sequence 4 bytes.
minTxInPayload = 9 + HASH_SIZE

# maxTxInPerMessage is the maximum number of transactions inputs that
# a transaction which fits into a message could possibly have.
maxTxInPerMessage = (wire.MaxMessagePayload / minTxInPayload) + 1

# MinTxOutPayload is the minimum payload size for a transaction output.
# Value 8 bytes + Varint for PkScript length 1 byte.
MinTxOutPayload = 9

# maxTxOutPerMessage is the maximum number of transactions outputs that
# a transaction which fits into a message could possibly have.
maxTxOutPerMessage = (wire.MaxMessagePayload / MinTxOutPayload) + 1

# minTxPayload is the minimum payload size for a transaction.  Note
# that any realistically usable transaction must have at least one
# input or output, but that is a rule enforced at a higher layer, so
# it is intentionally not included here.
# Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
# number of transaction outputs 1 byte + LockTime 4 bytes + min input
# payload + min output payload.
minTxPayload = 10

# freeListMaxScriptSize is the size of each buffer in the free list
# that	is used for deserializing scripts from the wire before they are
# concatenated into a single contiguous buffers.  This value was chosen
# because it is slightly more than twice the size of the vast majority
# of all "standard" scripts.  Larger scripts are still deserialized
# properly as the free list will simply be bypassed for them.
freeListMaxScriptSize = 512

# freeListMaxItems is the number of buffers to keep in the free list
# to use for script deserialization.  This value allows up to 100
# scripts per transaction being simultaneously deserialized by 125
# peers.  Thus, the peak usage of the free list is 12,500 * 512 =
# 6,400,000 bytes.
freeListMaxItems = 12500

# maxWitnessItemsPerInput is the maximum number of witness items to
# be read for the witness data for a single TxIn. This number is
# derived using a possble lower bound for the encoding of a witness
# item: 1 byte for length + 1 byte for the witness item itself, or two
# bytes. This value is then divided by the currently allowed maximum
# "cost" for a transaction.
maxWitnessItemsPerInput = 500000

# maxWitnessItemSize is the maximum allowed size for an item within
# an input's witness data. This number is derived from the fact that
# for script validation, each pushed item onto the stack must be less
# than 10k bytes.
maxWitnessItemSize = 11000

# TxFlagMarker is the first byte of the FLAG field in a bitcoin tx
# message. It allows decoders to distinguish a regular serialized
# transaction from one that would require a different parsing logic.
#
# Position of FLAG in a bitcoin tx message:
#   ┌─────────┬────────────────────┬─────────────┬─────┐
#   │ VERSION │ FLAG               │ TX-IN-COUNT │ ... │
#   │ 4 bytes │ 2 bytes (optional) │ varint      │     │
#   └─────────┴────────────────────┴─────────────┴─────┘
#
# Zooming into the FLAG field:
#   ┌── FLAG ─────────────┬────────┐
#   │ TxFlagMarker (0x00) │ TxFlag │
#   │ 1 byte              │ 1 byte │
#   └─────────────────────┴────────┘
TxFlagMarker = 0x00

# WitnessFlag is a flag specific to witness encoding. If the TxFlagMarker
# is encountered followed by the WitnessFlag, then it indicates a
# transaction has witness data. This allows decoders to distinguish a
# serialized transaction with witnesses from a legacy one.
WitnessFlag = 0x01

# BaseEncoding encodes all messages in the default format specified
# for the Bitcoin wire protocol.
BaseEncoding = 1 << 0

# WitnessEncoding encodes all messages other than transaction messages
# using the default Bitcoin wire protocol specification. For transaction
# messages, the new encoding format detailed in BIP0144 will be used.
WitnessEncoding = 1 << 1


class OutPoint:
    """
    OutPoint defines a Decred data type that is used to track previous
    transaction outputs.
    """

    def __init__(self, txHash: ByteArray, idx: int):
        self.hash = (
            txHash if txHash else ByteArray(0, length=HASH_SIZE)
        )
        self.index = idx

    def __eq__(self, other: 'OutPoint') -> bool:
        return (
            self.hash == other.hash
            and self.index == other.index
        )

    def txid(self) -> ByteArray:
        return reversed(self.hash).hex()

    def dict(self):
        return dict(
            hash=self.hash.hex(),
            index=self.index,
        )


class TxIn:
    """
    TxIn defines a Bitcoin transaction input.
    """

    def __init__(
        self,
        previousOutPoint: OutPoint,
        sequence: Optional[int] = MaxTxInSequenceNum,
        signatureScript: Optional[Union[ByteArray, None]] = None,
        witness: Optional[Union[List[ByteArray], None]] = None,
    ):
        self.previousOutPoint = previousOutPoint  # OutPoint
        self.sequence = sequence  # uint32
        self.signatureScript = signatureScript or ByteArray(b"")
        self.witness = witness or []

    def __eq__(self, ti: 'TxIn') -> bool:
        """
        Check whether all fields are equal.
        """
        return (
            self.previousOutPoint == ti.previousOutPoint
            and self.sequence == ti.sequence
            and self.signatureScript == ti.signatureScript
            and self.witness == ti.witness  # Or leave this off?
        )

    def serializeSize(self) -> int:
        """
        serializeSize returns the number of bytes it would take to serialize the
        the transaction input.
        """
        # Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
        # serialized varint size for the length of SignatureScript +
        # SignatureScript bytes.
        return 40 + dcrwire.varIntSerializeSize(len(self.signatureScript)) + len(self.signatureScript)

    def witnessSerializeSize(self) -> int:
        """
        serializeSize returns the number of bytes it would take to serialize the
        transaction input's witness.
        """
        # A varint to signal the number of elements the witness has.
        n = dcrwire.varIntSerializeSize(len(self.witness))

        # For each element in the witness, we'll need a varint to signal the
        # size of the element, then finally the number of bytes the element
        # itself comprises.
        for witItem in self.witness:
            n += dcrwire.varIntSerializeSize(len(witItem))
            n += len(witItem)

        return n


class TxOut:
    """
    TxOut defines a Bitcoin transaction output.
    """

    def __init__(
        self,
        value: Optional[int] = 0,
        pkScript: Optional[Union[ByteArray, None]] = None,
        version: Optional[int] = 0,
    ):
        self.value = value
        self.version = version
        self.pkScript = pkScript or ByteArray()

    def serializeSize(self):
        """
        SerializeSize returns the number of bytes it would take to serialize the
        the transaction output.
        """
        return 8 + dcrwire.varIntSerializeSize(len(self.pkScript)) + len(self.pkScript)

    def __eq__(self, to: 'TxOut') -> bool:
        """
        Check for all identical fields.
        """
        return (
            self.value == to.value
            and self.version == to.version
            and self.pkScript == to.pkScript
        )


class MsgTx:
    """
    MsgTx implements the Message interface and represents a Bitcoin tx message.
    It is used to deliver transaction information in response to a getdata
    message (MsgGetData) for a given transaction.

    Use the addTxIn and addTxOut functions to build up the list of transaction
    inputs and outputs.
    """
    def __init__(
        self,
        version: Optional[int] = 1,
        txIn: Optional[Union[List[TxIn], None]] = None,
        txOut: Optional[Union[List[TxOut], None]] = None,
        lockTime: Optional[int] = 0,
    ):
        self.version = version
        self.txIn = txIn or []
        self.txOut = txOut or []
        self.lockTime = lockTime

    def __eq__(self, tx):
        """
        Check equality of all fields. Useful in testing.
        """
        return (
            self.version == tx.version
            and all((a == b for a, b in zip(self.txIn, tx.txIn)))
            and all((a == b for a, b in zip(self.txOut, tx.txOut)))
            and self.lockTime == tx.lockTime
        )

    def addTxIn(self, ti: TxIn):
        """addTxIn adds a transaction input to the message."""
        self.txIn.append(ti)

    def addTxOut(self, to: TxOut):
        """addTxOut adds a transaction output to the message."""
        self.txOut.append(to)

    def hash(self) -> ByteArray:
        """txHash generates the hash for the transaction."""
        # Encode the transaction and calculate double sha256 on the result.
        # Ignore the error returns since the only way the encode could fail
        # is being out of memory or due to nil pointers, both of which would
        # cause a run-time panic.
        expSize = self.serializeSizeStripped()
        toHash = self.serializeNoWitness()
        if len(toHash) != expSize:
            raise DecredError(f"txHash: expected {expSize}-byte serialization, got {len(toHash)} bytes")
        return doubleHashH(toHash.bytes())

    def witnessHash(self) -> ByteArray:
        """
        witnessHash generates the hash of the transaction serialized according
        to the new witness serialization defined in BIP0141 and BIP0144. The
        final output is used within the Segregated Witness commitment of all the
        witnesses within a block. If a transaction has no witness data, then the
        witness hash, is the same as its txid.
        """
        if self.hasWitness():
            expSize = self.serializeSize()
            toHash = self.serialize()
            if len(toHash) != expSize:
                raise DecredError(f"witnessHash: expected {expSize}-byte serialization, got {len(toHash)} bytes")
            return doubleHashH(toHash.bytes())

        return self.hash()

    def copy(self) -> 'MsgTx':
        """
        copy creates a deep copy of a transaction so that the original does not get
        modified when the copy is manipulated.
        """
        # Create new tx and start by copying primitive values and making space
        # for the transaction inputs and outputs.
        newTx = MsgTx(
            version=self.version,
            lockTime=self.lockTime,
        )

        # Deep copy the old TxIn data.
        for oldTxIn in self.TxIn:
            # Deep copy the old previous outpoint.
            oldOutPoint = oldTxIn.previousOutPoint
            newOP = OutPoint(txHash=oldOutPoint.hash.copy(), idx=oldOutPoint.index)

            # Create new txIn with the deep copied data.
            # Deep copy the old signature script.

            newTxIn = TxIn(
                previousOutPoint=newOP,
                sequence=oldTxIn.sequence,
                signatureScript=oldTxIn.signatureScript.copy(),
                witness=[b.copy() for b in oldTxIn.witness],
            )

            # Finally, append this fully copied txin.
            newTx.txIn.append(newTxIn)

        # Deep copy the old TxOut data.
        for oldTxOut in self.txOut:
            # Deep copy the old PkScript
            newTx.txOut.append(TxOut(value=oldTxOut.value, pkScript=oldTxOut.pkScript.copy()))

        return newTx

    @staticmethod
    def btcDecode(b: ByteArray, pver: int, enc: int) -> 'MsgTx':
        """
        btcDecode decodes b using the Bitcoin protocol encoding. This is part of
        the Message API. See deserialize for decoding transactions stored to
        disk, such as in a database, as opposed to decoding transactions from
        the wire.
        """
        # The serialized encoding of the version includes the real transaction
        # version in the lower 16 bits and the transaction serialization type
        # in the upper 16 bits.

        version = b.pop(4).unLittle().int()

        tx = MsgTx(version=version)

        count = dcrwire.readVarInt(b, pver)

        # A count of zero (meaning no TxIn's to the uninitiated) means that the
        # value is a TxFlagMarker, and hence indicates the presence of a flag.
        flag = [0]
        if count == TxFlagMarker and enc == WitnessEncoding:
            # The count varint was in fact the flag marker byte. Next, we need to
            # read the flag value, which is a single byte.
            flag = b.pop(1)

            # At the moment, the flag MUST be WitnessFlag (0x01). In the future
            # other flag types may be supported.
            if flag[0] != WitnessFlag:
                raise DecredError(f"MsgTx.BtcDecode: witness tx but flag byte is {flag}.")

            # With the Segregated Witness specific fields decoded, we can
            # now read in the actual txin count.
            count = dcrwire.readVarInt(b, pver)

        # Prevent more input transactions than could possibly fit into a
        # message.  It would be possible to cause memory exhaustion
        # without a sane upper bound on this count.
        if count > maxTxInPerMessage:
            raise DecredError(f"MsgTx.BtcDecode: too many input transactions to fit into  max message size [count {count}, max {maxTxInPerMessage}]")

        # Deserialize the inputs.
        totalScriptSize = 0
        for i in range(count):
            # The pointer is set now in case a script buffer is borrowed
            # and needs to be returned to the pool on error.
            ti = readTxIn(b, pver, tx.version)
            tx.addTxIn(ti)
            totalScriptSize += len(ti.signatureScript)

        count = dcrwire.readVarInt(b, pver)

        # Prevent more output transactions than could possibly fit into a
        # message.  It would be possible to cause memory exhaustion and panics
        # without a sane upper bound on this count.
        if count > maxTxOutPerMessage:
            raise DecredError(f"MsgTx.btcDecode: too many output transactions to fit into max message size [count {count}, max {maxTxOutPerMessage}]")

        # Deserialize the outputs.
        for _ in range(count):
            # The pointer is set now in case a script buffer is borrowed
            # and needs to be returned to the pool on error.
            txOut = readTxOut(b, pver, tx.version)
            tx.addTxOut(txOut)
            totalScriptSize += len(txOut.pkScript)

        # If the transaction's flag byte isn't 0x00 at this point, then one or
        # more of its inputs has accompanying witness data.
        if flag[0] != 0 and enc == WitnessEncoding:
            for txIn in tx.txIn:
                # For each input, the witness is encoded as a stack
                # with one or more items. Therefore, we first read a
                # varint which encodes the number of stack items.
                witCount = dcrwire.readVarInt(b, pver)

                # Prevent a possible memory exhaustion attack by
                # limiting the witCount value to a sane upper bound.
                if witCount > maxWitnessItemsPerInput:
                    raise DecredError(f"too many witness items to fit into max message size [count {witCount}, max {maxWitnessItemsPerInput}]")

                # Then for witCount number of stack items, each item
                # has a varint length prefix, followed by the witness
                # item itself.
                for j in range(witCount):
                    script = readScript(b, pver, maxWitnessItemSize, "script witness item")
                    txIn.witness.append(script)
                    totalScriptSize += len(script)

        tx.lockTime = b.pop(4).unLittle().int()

        # btcwallet takes some cautions here to make sure all scripts in the
        # transaction are collected into a single contiguous buffer in order to
        # lower the garbage collector workload. It might be worth investigating
        # whether such an approach, which should be possible on Python with
        # memoryviews, would actually provide a worthwhile perf boost.

        return tx

    @staticmethod
    def deserialize(b):
        """Deserialize the MsgTx."""
        return MsgTx.btcDecode(b, 0, WitnessEncoding)

    @staticmethod
    def deserializeNoWitness(b):
        """Deserialize the MsgTx without witness data."""
        return MsgTx.btcDecode(b, 0, BaseEncoding)

    def btcEncode(self, pver: int, enc: int) -> ByteArray:
        """
        btcEncode encodes the bytes using the Bitcoin protocol encoding. This is
        part of the Message interface implementation. See serialize for encoding
        transactions to be stored to disk, such as in a database, as opposed to
        encoding transactions for the wire.
        """
        b = ByteArray(self.version, length=4).littleEndian()

        # If the encoding version is set to WitnessEncoding, and the Flags
        # field for the MsgTx aren't 0x00, then this indicates the transaction
        # is to be encoded using the new witness inclusionary structure
        # defined in BIP0144.
        doWitness = enc == WitnessEncoding and self.hasWitness()
        if doWitness:
            # After the transaction's Version field, we include two additional
            # bytes specific to the witness encoding. This byte sequence is known
            # as a flag. The first byte is a marker byte (TxFlagMarker) and the
            # second one is the flag value to indicate presence of witness data.
            b += TxFlagMarker
            b += WitnessFlag

        count = len(self.txIn)
        b += dcrwire.writeVarInt(pver, count)

        for ti in self.txIn:
            b += writeTxIn(pver, self.version, ti)

        count = len(self.txOut)
        b += dcrwire.writeVarInt(pver, count)
        for to in self.txOut:
            b += writeTxOut(pver, self.version, to)

        # If this transaction is a witness transaction, and the witness
        # encoded is desired, then encode the witness for each of the inputs
        # within the transaction.
        if doWitness:
            for ti in self.txIn:
                b += writeTxWitness(pver, self.version, ti.witness)

        b += ByteArray(self.lockTime, length=4).littleEndian()

        return b

    def hasWitness(self) -> bool:
        """
        hasWitness returns False if none of the inputs within the transaction
        contain witness data, True otherwise.
        """
        for txIn in self.txIn:
            if len(txIn.witness) != 0:
                return True
        return False

    def serialize(self) -> ByteArray:
        """
        serialize encodes the transaction using a format that is suitable for
        long-term storage such as a database while respecting the version field
        in the transaction.  This function differs from btcEncode in that
        btcEncode encodes the transaction to the bitcoin wire protocol in order
        to be sent across the network.  The wire encoding can technically differ
        depending on the protocol version and doesn't even really need to match
        the format of a stored transaction at all.  As of the time this comment
        was written, the encoded transaction is the same in both instances, but
        there is a distinct difference and separating the two allows the API to
        be flexible enough to deal with changes.
        """
        return self.btcEncode(0, WitnessEncoding)

    def serializeNoWitness(self) -> ByteArray:
        """
        serializeNoWitness encodes the transaction in an identical manner to
        Serialize, however even if the source transaction has inputs with
        witness data, the old serialization format will still be used.
        """
        return self.btcEncode(0, BaseEncoding)

    def baseSize(self) -> int:
        """
        baseSize returns the serialized size of the transaction without
        accounting for any witness data.
        """
        # Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
        # number of transaction inputs and outputs.
        n = 8 + dcrwire.varIntSerializeSize(len(self.txIn)) + dcrwire.varIntSerializeSize(len(self.txOut))

        for txIn in self.txIn:
            n += txIn.serializeSize()

        for txOut in self.txOut:
            n += txOut.serializeSize()

        return n

    def serializeSize(self) -> int:
        """
        serializeSize returns the number of bytes it would take to serialize the
        the transaction.
        """
        n = self.baseSize()

        if self.hasWitness():
            # The marker, and flag fields take up two additional bytes.
            n += 2

            # witnesses for each txin.
            # Additionally, factor in the serialized size of each of the
            for txIn in self.txIn:
                n += txIn.witnessSerializeSize()

        return n

    def serializeSizeStripped(self) -> int:
        """
        serializeSizeStripped returns the number of bytes it would take to serialize
        the transaction, excluding any included witness data.
        """
        return self.baseSize()

    def command(self) -> str:
        """
        command returns the protocol command string for the message.  This is
        part of the Message interface implementation.
        """
        return wire.CmdTx

    def maxPayloadLength(self, pver: int) -> int:
        """
        maxPayloadLength returns the maximum length the payload can be. This is
        part of the Message interface implementation.
        """
        return wire.MaxBlockPayload

    def pkScriptLocs(self) -> List[int]:
        """
        pkScriptLocs returns a slice containing the start of each public key
        script within the raw serialized transaction.  The caller can easily
        obtain the length of each script by using len on the script available
        via the appropriate transaction output entry.
        """
        numTxOut = len(self.txOut)
        if numTxOut == 0:
            return []

        # The starting offset in the serialized transaction of the first
        # transaction output is:
        #
        # Version 4 bytes + serialized varint size for the number of
        # transaction inputs and outputs + serialized size of each transaction
        # input.
        n = 4 + dcrwire.varIntSerializeSize(len(self.txIn)) + dcrwire.varIntSerializeSize(numTxOut)

        # If this transaction has a witness input, the an additional two bytes
        # for the marker, and flag byte need to be taken into account.
        if len(self.txIn) > 0 and self.txIn[0].witness:
            n += 2

        for txIn in self.txIn:
            n += txIn.serializeSize()

        # Calculate and set the appropriate offset for each public key script.
        pkScriptLocs = []
        for i, txOut in enumerate(self.txOut):
            # The offset of the script in the transaction output is:
            #
            # Value 8 bytes + serialized varint size for the length of
            # PkScript.
            n += 8 + dcrwire.varIntSerializeSize(len(txOut.pkScript))
            pkScriptLocs.append(n)
            n += len(txOut.pkScript)

        return pkScriptLocs


def readOutPoint(b: ByteArray, pver: int, version: int) -> OutPoint:
    """
    readOutPoint reads the next sequence of bytes from b, removing the sequence
    from b returning both.
    """
    return OutPoint(
        txHash=b.pop(HASH_SIZE),
        idx=b.pop(4).unLittle().int(),
    )


def writeOutPoint(pver: int, version: int, op: OutPoint) -> ByteArray:
    """
    writeOutPoint serializes the OutPoint.
    """
    return op.hash + ByteArray(op.index, length=4).littleEndian()


def readScript(b: ByteArray, pver: int, maxAllowed: int, fieldName: str) -> ByteArray:
    """
    readScript reads a variable length byte array that represents a transaction
    script.  It is encoded as a varInt containing the length of the array
    followed by the bytes themselves.  An error is returned if the length is
    greater than the passed maxAllowed parameter which helps protect against
    memory exhaustion attacks and forced panics through malformed messages.  The
    fieldName parameter is only used for the error message so it provides more
    context in the error.
    """
    count = dcrwire.readVarInt(b, pver)

    # Prevent byte array larger than the max message size.  It would
    # be possible to cause memory exhaustion and panics without a sane
    # upper bound on this count.
    if count > maxAllowed:
        raise DecredError(f"readScript: {fieldName} is larger than the max allowed size [count {count}, max {maxAllowed}]", fieldName, count, maxAllowed)

    return b.pop(count)


def readTxIn(b: ByteArray, pver: int, version: int) -> TxIn:
    """
    readTxIn reads and decodes the next sequence of bytes from b as a
    transaction input (TxIn).
    """
    return TxIn(
        previousOutPoint=readOutPoint(b, pver, version),
        signatureScript=readScript(b, pver, wire.MaxMessagePayload, "transaction input signature script"),
        sequence=b.pop(4).unLittle().int(),
    )


def writeTxIn(pver: int, version: int, ti: TxIn) -> ByteArray:
    """
    writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
    input (TxIn).
    """
    b = writeOutPoint(pver, version, ti.previousOutPoint)
    b += dcrwire.writeVarBytes(pver, ti.signatureScript)
    return b + ByteArray(ti.sequence, length=4).littleEndian()


def readTxOut(b: ByteArray, pver: int, version: int) -> TxOut:
    """
    readTxOut reads the next sequence of bytes from b as a transaction output
    (TxOut).
    """
    return TxOut(
        value=b.pop(8).unLittle().int(),
        pkScript=readScript(b, pver, wire.MaxMessagePayload, "transaction output public key script"),
    )


def writeTxOut(pver: int, version: int, to: TxOut) -> ByteArray:
    """
    writeTxOut encodes to into the bitcoin protocol encoding for a transaction
    output (TxOut).
    """
    b = ByteArray(to.value, length=8).littleEndian()
    return b + dcrwire.writeVarBytes(pver, to.pkScript)


def writeTxWitness(pver: int, version: int, wit: List[ByteArray]) -> ByteArray:
    """
    writeTxWitness encodes the bitcoin protocol encoding for a transaction
    input's witness.
    """
    b = dcrwire.writeVarInt(pver, len(wit))
    for item in wit:
        b += dcrwire.writeVarBytes(pver, item)
    return b


def doubleHashH(b: bytes) -> bytes:
    """
    Double-SHA256 hash.
    """
    v = hashlib.sha256(b).digest()
    return hashlib.sha256(v).digest()
