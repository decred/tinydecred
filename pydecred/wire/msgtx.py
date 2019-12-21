"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

Based on dcrd MsgTx.
"""

from tinydecred.util.encode import ByteArray
from tinydecred.crypto.crypto import hashH
from tinydecred.pydecred.wire import wire


# TxVersion is the current latest supported transaction version.
TxVersion = 1  # go type uint16

# TxTreeRegular is the value for a normal transaction tree for a
# transaction's location in a block.
TxTreeRegular = 0  # go type int8

# TxTreeStake is the value for a stake transaction tree for a
# transaction's location in a block.
TxTreeStake = 1  # go type int8

# chainhash.HashSize in go
HASH_SIZE = 32

# minTxInPayload is the minimum payload size for a transaction input.
# PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes +
# PreviousOutPoint.Tree 1 byte + Varint for SignatureScript length 1
# byte + Sequence 4 bytes.
minTxInPayload = 11 + HASH_SIZE

# maxTxInPerMessage is the maximum number of transactions inputs that
# a transaction which fits into a message could possibly have.
maxTxInPerMessage = (wire.MaxMessagePayload // minTxInPayload) + 1

# minTxOutPayload is the minimum payload size for a transaction output.
# Value 8 bytes + Varint for PkScript length 1 byte.
minTxOutPayload = 9

# maxTxOutPerMessage is the maximum number of transactions outputs that
# a transaction which fits into a message could possibly have.
maxTxOutPerMessage = (wire.MaxMessagePayload // minTxOutPayload) + 1

# MaxTxInSequenceNum is the maximum sequence number the sequence field
# of a transaction input can be.
MaxTxInSequenceNum = 0xFFFFFFFF


def writeOutPoint(pver, ver, op):
    # w io.Writer, pver uint32, version uint16, op *OutPoint) error {
    """
    writeOutPoint encodes op to the Decred protocol encoding for an OutPoint
    to w.
    """
    b = op.hash.copy()
    b += ByteArray(op.index, length=4).littleEndian()
    b += ByteArray(op.tree, length=1)
    return b


def readOutPoint(b, pver, ver):
    # r io.Reader, pver uint32, version uint16, op *OutPoint) error {
    """
    readOutPoint reads the next sequence of bytes from r as an OutPoint.
    """
    op = OutPoint(None, None, None)
    op.hash = b.pop(HASH_SIZE)
    op.index = b.pop(4).unLittle().int()
    op.tree = b.pop(1).int()
    return b, op


def readTxInPrefix(b, pver, serType, ver, ti):
    # r io.Reader, pver uint32, serType TxSerializeType, version uint16, ti *TxIn) error {
    if serType == wire.TxSerializeOnlyWitness:
        raise Exception(
            "readTxInPrefix: tried to read a prefix input for a witness only tx"
        )

    # Outpoint.
    b, ti.previousOutPoint = readOutPoint(b, pver, ver)

    # Sequence.
    ti.sequence = b.pop(4).unLittle().int()


def writeTxInPrefix(pver, ver, ti):
    # pver uint32, version uint16, ti *TxIn) error {
    """
    writeTxInPrefixs encodes ti to the Decred protocol encoding for a transaction
    input (TxIn) prefix to w.
    """
    b = writeOutPoint(pver, ver, ti.previousOutPoint)
    b += ByteArray(ti.sequence, length=4).littleEndian()
    return b


def writeTxInWitness(pver, ver, ti):
    # w io.Writer, pver uint32, version uint16, ti *TxIn) error {
    """
    writeTxWitness encodes ti to the Decred protocol encoding for a transaction
    input (TxIn) witness to w.
    """
    # ValueIn
    b = ByteArray(ti.valueIn, length=8).littleEndian()

    # BlockHeight.
    b += ByteArray(ti.blockHeight, length=4).littleEndian()

    # BlockIndex.
    b += ByteArray(ti.blockIndex, length=4).littleEndian()

    # Write the signature script.
    b += wire.writeVarBytes(pver, ti.signatureScript)
    return b


def readScript(b, pver, maxAllowed, fieldName):
    # r io.Reader, pver uint32, maxAllowed uint32, fieldName string) ([]byte, error) {
    """
    readScript reads a variable length byte array that represents a transaction
    script.  It is encoded as a varInt containing the length of the array
    followed by the bytes themselves.  An error is returned if the length is
    greater than the passed maxAllowed parameter which helps protect against
    memory exhaustion attacks and forced panics thorugh malformed messages.  The
    fieldName parameter is only used for the error message so it provides more
    context in the error.
    """
    count = wire.readVarInt(b, pver)

    # Prevent byte array larger than the max message size.  It would
    # be possible to cause memory exhaustion and panics without a sane
    # upper bound on this count.
    if count > maxAllowed:
        raise Exception(
            "readScript: %s is larger than the max allowed size [count %d, max %d]"
            % (fieldName, count, maxAllowed)
        )

    a = b.pop(count)

    return b, a


def readTxInWitness(b, pver, ver, ti):
    # r io.Reader, pver uint32, version uint16, ti *TxIn) error {
    """
    readTxInWitness reads the next sequence of bytes from r as a transaction input
    (TxIn) in the transaction witness.
    """
    # ValueIn.
    ti.valueIn = b.pop(8).unLittle().int()

    # BlockHeight.
    ti.blockHeight = b.pop(4).unLittle().int()

    # BlockIndex.
    ti.blockIndex = b.pop(4).unLittle().int()

    # Signature script.
    b, ti.signatureScript = readScript(
        b, pver, wire.MaxMessagePayload, "transaction input signature script"
    )

    return b


def readTxOut(b, pver, ver, to):
    # r io.Reader, pver uint32, version uint16, to *TxOut) error {
    """
    # readTxOut reads the next sequence of bytes from r as a transaction output (TxOut).
    """
    to.value = b.pop(8).unLittle().int()
    to.version = b.pop(2).unLittle().int()
    b, to.pkScript = readScript(
        b, pver, wire.MaxMessagePayload, "transaction output public key script"
    )
    return b


def writeTxOut(pver, ver, to):
    # w io.Writer, pver uint32, version uint16, to *TxOut) error {
    """
    writeTxOut encodes to into the Decred protocol encoding for a transaction
    output (TxOut) to w.
    """
    b = ByteArray(to.value, length=8).littleEndian()
    b += ByteArray(to.version, length=2).littleEndian()
    b += wire.writeVarBytes(pver, to.pkScript)
    return b


# def writeTxScriptsToMsgTx(msg, totalScriptSize, serType):
#   # msg *MsgTx, totalScriptSize uint64, serType TxSerializeType) {
#   """
#   writeTxScriptsToMsgTx allocates the memory for variable length fields in a
#   MsgTx TxIns, TxOuts, or both as a contiguous chunk of memory, then fills
#   in these fields for the MsgTx by copying to a contiguous piece of memory
#   and setting the pointer.

#   NOTE: It is no longer valid to return any previously borrowed script
#   buffers after this function has run because it is already done and the
#   scripts in the transaction inputs and outputs no longer point to the
#   buffers.

#   Create a single allocation to house all of the scripts and set each
#   input signature scripts and output public key scripts to the
#   appropriate subslice of the overall contiguous buffer.  Then, return
#   each individual script buffer back to the pool so they can be reused
#   for future deserializations.  This is done because it significantly
#   reduces the number of allocations the garbage collector needs to track,
#   which in turn improves performance and drastically reduces the amount
#   of runtime overhead that would otherwise be needed to keep track of
#   millions of small allocations.

#   Closures around writing the TxIn and TxOut scripts are used in Decred
#   because, depending on the serialization type desired, only input or
#   output scripts may be required.
#   """
#   offset = 0
#   scripts = ByteArray(0, length=totalScriptSize)

#   def writeTxIns():
#       nonlocal offset, scripts
#       for txIn in msg.txIn:
#           # Copy the signature script into the contiguous buffer at the
#           # appropriate offset.
#           signatureScript = txIn.signatureScript
#           scripts[offset] = signatureScript

#           # Reset the signature script of the transaction input to the
#           # slice of the contiguous buffer where the script lives.
#           scriptSize = len(signatureScript)
#           end = offset + scriptSize
#           txIn.signatureScript = scripts[offset:end]
#           offset += scriptSize

#   def writeTxOuts():
#       nonlocal offset, scripts
#       for txOut in msg.txOut:
#           # Copy the public key script into the contiguous buffer at the
#           # appropriate offset.
#           pkScript = txOut.pkScript
#           scripts[offset] = pkScript

#           # Reset the public key script of the transaction output to the
#           # slice of the contiguous buffer where the script lives.
#           scriptSize = len(pkScript)
#           end = offset + scriptSize
#           txOut.pkScript = scripts[offset:end:end]
#           offset += scriptSize

#           # Return the temporary script buffer to the pool.
#           scriptPool.Return(pkScript)
#       }
#   }

#   // Handle the serialization types accordingly.
#   switch serType {
#   case TxSerializeNoWitness:
#       writeTxOuts()
#   case TxSerializeOnlyWitness:
#       fallthrough
#   case TxSerializeFull:
#       writeTxIns()
#       writeTxOuts()
#   }
# }


class TxIn:
    """
    TxIn defines a Decred transaction input.
    """

    def __init__(
        self,
        previousOutPoint,
        sequence=MaxTxInSequenceNum,
        valueIn=0,
        blockHeight=0,
        blockIndex=0,
        signatureScript=None,
    ):
        # Non-witness
        self.previousOutPoint = previousOutPoint  # OutPoint
        self.sequence = sequence  # uint32

        # Witness
        self.valueIn = valueIn  # int64
        self.blockHeight = blockHeight  # uint32
        self.blockIndex = blockIndex  # uint32
        self.signatureScript = (
            signatureScript if signatureScript else ByteArray(b"")
        )  # []byte

    def serializeSizePrefix(self):
        """
        SerializeSizePrefix returns the number of bytes it would take to serialize
        the transaction input for a prefix.
        Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Outpoint Tree 1 byte +
        Sequence 4 bytes.
        """
        return 41

    def serializeSizeWitness(self):
        """
        SerializeSizeWitness returns the number of bytes it would take to serialize the
        transaction input for a witness.
        ValueIn (8 bytes) + BlockHeight (4 bytes) + BlockIndex (4 bytes) +
        serialized varint size for the length of SignatureScript +
        SignatureScript bytes.
        """
        return (
            8
            + 4
            + 4
            + wire.varIntSerializeSize(len(self.signatureScript))
            + len(self.signatureScript)
        )

    def __eq__(self, ti):
        """
        Check whether all fields are equal
        """
        a = (
            self.previousOutPoint == ti.previousOutPoint
            and self.sequence == ti.sequence
            and self.valueIn == ti.valueIn
            and self.blockHeight == ti.blockHeight
            and self.blockIndex == ti.blockIndex
            and self.signatureScript == ti.signatureScript
        )
        return a


class TxOut:
    """
    TxOut defines a Decred transaction output.
    """

    def __init__(self, value=0, pkScript=None, version=0):
        self.value = value  # int64
        self.version = version  # uint16
        self.pkScript = pkScript if pkScript else ByteArray(b"")  # []byte

    def serializeSize(self):
        """
        SerializeSize returns the number of bytes it would take to serialize the
        the transaction output.
        Value 8 bytes + Version 2 bytes + serialized varint size for
        the length of PkScript + PkScript bytes.
        """
        return 8 + 2 + wire.varIntSerializeSize(len(self.pkScript)) + len(self.pkScript)

    def __eq__(self, to):
        """
        Check for all identical fields.
        """
        return (
            self.value == to.value
            and self.version == to.version
            and self.pkScript == to.pkScript
        )


class OutPoint:
    """
    OutPoint defines a Decred data type that is used to track previous
    transaction outputs.
    """

    def __init__(self, txHash, idx, tree):
        self.hash = (
            txHash if txHash else ByteArray(0, length=HASH_SIZE)
        )  # chainhash.Hash
        self.index = idx  # uint32
        self.tree = tree  # int8

    def __eq__(self, other):
        return (
            self.hash == other.hash
            and self.index == other.index
            and self.tree == other.tree
        )

    def txid(self):
        return reversed(self.hash).hex()


class MsgTx:
    """
    MsgTx implements the Message interface and represents a Decred tx message.
    It is used to deliver transaction information in response to a getdata
    message (MsgGetData) for a given transaction.

    Use the AddTxIn and AddTxOut functions to build up the list of transaction
    inputs and outputs.

    The go types are
    cachedHash *chainhash.Hash
    serType    TxSerializeType
    version    uint16
    txIn       []*TxIn
    txOut      []*TxOut
    lockTime   uint32
    expiry     uint32
    """

    def __init__(self, cachedHash, serType, version, txIn, txOut, lockTime, expiry):
        self.cachedHash = cachedHash
        self.serType = serType
        self.version = version
        self.txIn = txIn
        self.txOut = txOut
        self.lockTime = lockTime
        self.expiry = expiry

    @staticmethod
    def new():
        """
        Return a fully serialized version 1 transaction. Python equivalent of
        NewMsgTx in Go.
        """
        return MsgTx(
            cachedHash=None,
            serType=wire.TxSerializeFull,
            version=TxVersion,
            txIn=[],
            txOut=[],
            lockTime=0,
            expiry=0,
        )

    def __eq__(self, tx):
        """
        Check equality of all fields. Useful in testing.
        """
        return (
            self.cachedHash == tx.cachedHash
            and self.serType == tx.serType
            and self.version == tx.version
            and all((a == b for a, b in zip(self.txIn, tx.txIn)))
            and all((a == b for a, b in zip(self.txOut, tx.txOut)))
            and self.lockTime == tx.lockTime
            and self.expiry == tx.expiry
        )

    def addTxIn(self, txin):
        self.txIn.append(txin)

    def addTxOut(self, txout):
        self.txOut.append(txout)

    def hash(self):  # chainhash.Hash {
        """
        TxHash generates the hash for the transaction prefix.  Since it does not
        contain any witness data, it is not malleable and therefore is stable for
        use in unconfirmed transaction chains.
        """
        # TxHash should always calculate a non-witnessed hash.
        toHash = self.mustSerialize(wire.TxSerializeNoWitness)
        # If this hash is converted to a hex string, it should be reversed first.
        return hashH(toHash.bytes())

    def txHex(self):
        return self.serialize()

    def txid(self):
        """
        Hex encoded, byte-reversed tx hash.
        """
        return reversed(self.hash()).hex()

    def id(self):
        return self.txid()

    def command(self):
        """
        Command returns the protocol command string for the message.  This is part
        of the Message interface implementation in go.
        """
        return wire.CmdTx

    def maxPayloadLength(self, pver):
        """
        MaxPayloadLength returns the maximum length the payload can be for the
        receiver.  This is part of the Message interface implementation.
        """
        # Protocol version 3 and lower have a different max block payload.
        if pver <= 3:
            return wire.MaxBlockPayloadV3
        return wire.MaxBlockPayload

    def mustSerialize(self, serType):
        """
        mustSerialize returns the serialization of the transaction for the provided
        serialization type without modifying the original transaction.  It will panic
        if any errors occur.
        """
        ogSerType = self.serType
        self.serType = serType
        serialized = self.serialize()
        self.serType = ogSerType
        return serialized

    def encodePrefix(self, pver):
        """
        encodePrefix encodes a transaction prefix into a writer.
        """
        count = len(self.txIn)
        b = wire.writeVarInt(pver, count)
        for ti in self.txIn:
            b += writeTxInPrefix(pver, self.version, ti)

        count = len(self.txOut)
        b += wire.writeVarInt(pver, count)

        for to in self.txOut:
            b += writeTxOut(pver, self.version, to)
        b += ByteArray(self.lockTime, length=4).littleEndian()
        b += ByteArray(self.expiry, length=4).littleEndian()

        return b

    def encodeWitness(self, pver):
        # w io.Writer, pver uint32) error {
        """
        encodeWitness encodes a transaction witness into a writer.
        """
        count = len(self.txIn)
        b = wire.writeVarInt(pver, count)

        for ti in self.txIn:
            b += writeTxInWitness(pver, self.version, ti)

        return b

    def btcEncode(self, pver):
        # w io.Writer, pver uint32) error {
        """
        BtcEncode encodes the receiver to w using the Decred protocol encoding.
        This is part of the Message interface implementation.
        See Serialize for encoding transactions to be stored to disk, such as in a
        database, as opposed to encoding transactions for the wire.
        """
        # The serialized encoding of the version includes the real transaction
        # version in the lower 16 bits and the transaction serialization type
        # in the upper 16 bits.
        b = ByteArray(self.version | (self.serType << 16), length=4).littleEndian()

        if self.serType == wire.TxSerializeNoWitness:
            b += self.encodePrefix(pver)

        elif self.serType == wire.TxSerializeOnlyWitness:
            b += self.encodeWitness(pver)

        elif self.serType == wire.TxSerializeFull:
            b += self.encodePrefix(pver)
            b += self.encodeWitness(pver)

        else:
            raise Exception("MsgTx.BtcEncode: unsupported transaction type")

        return b

    def serializeSize(self):
        """
        SerializeSize returns the number of bytes it would take to serialize the
        the transaction.
        """
        # Unknown type return 0.
        n = 0

        if self.serType == wire.TxSerializeNoWitness:
            # Version 4 bytes + LockTime 4 bytes + Expiry 4 bytes +
            # Serialized varint size for the number of transaction
            # inputs and outputs.
            n = (
                12
                + wire.varIntSerializeSize(len(self.txIn))
                + wire.varIntSerializeSize(len(self.txOut))
            )

            for txIn in self.txIn:
                n += txIn.serializeSizePrefix()
            for txOut in self.txOut:
                n += txOut.serializeSize()

        elif self.serType == wire.TxSerializeOnlyWitness:
            # Version 4 bytes + Serialized varint size for the
            # number of transaction signatures.
            n = 4 + wire.varIntSerializeSize(len(self.txIn))

            for txIn in self.txIn:
                n += txIn.serializeSizeWitness()

        elif self.serType == wire.TxSerializeFull:
            # Version 4 bytes + LockTime 4 bytes + Expiry 4 bytes + Serialized
            # varint size for the number of transaction inputs (x2) and
            # outputs. The number of inputs is added twice because it's
            # encoded once in both the witness and the prefix.
            n = (
                12
                + wire.varIntSerializeSize(len(self.txIn))
                + wire.varIntSerializeSize(len(self.txIn))
                + wire.varIntSerializeSize(len(self.txOut))
            )

            for txIn in self.txIn:
                n += txIn.serializeSizePrefix()
            for txIn in self.txIn:
                n += txIn.serializeSizeWitness()
            for txOut in self.txOut:
                n += txOut.serializeSize()
        return n

    def decodePrefix(self, b, pver):
        # r io.Reader, pver uint32) (uint64, error) {
        """
        decodePrefix decodes a transaction prefix and stores the contents
        in the embedded msgTx.
        """
        count = wire.readVarInt(b, pver)
        # Prevent more input transactions than could possibly fit into a
        # message.  It would be possible to cause memory exhaustion and panics
        # without a sane upper bound on this count.
        if count > maxTxInPerMessage:
            raise Exception(
                "MsgTx.decodePrefix: too many input transactions to fit into"
                " max message size [count %d, max %d]" % (count, maxTxInPerMessage)
            )

        # TxIns.
        txIns = self.txIn = [TxIn(None, 0) for i in range(count)]
        for txIn in txIns:
            readTxInPrefix(b, pver, self.serType, self.version, txIn)

        count = wire.readVarInt(b, pver)

        # Prevent more output transactions than could possibly fit into a
        # message.  It would be possible to cause memory exhaustion and panics
        # without a sane upper bound on this count.
        if count > maxTxOutPerMessage:
            raise Exception(
                "MsgTx.decodePrefix: too many output transactions to fit into"
                " max message size [count %d, max %d]" % (count, maxTxOutPerMessage)
            )

        # TxOuts.
        totalScriptSize = 0
        txOuts = self.txOut = [TxOut(None, None) for i in range(count)]
        for txOut in txOuts:
            # The pointer is set now in case a script buffer is borrowed
            # and needs to be returned to the pool on error.
            b = readTxOut(b, pver, self.version, txOut)
            totalScriptSize += len(txOut.pkScript)

        # Locktime and expiry.
        self.lockTime = b.pop(4).unLittle().int()

        self.expiry = b.pop(4).unLittle().int()
        return b, totalScriptSize

    def decodeWitness(self, b, pver, isFull):
        # r io.Reader, pver uint32, isFull bool) (uint64, error) {
        # Witness only; generate the TxIn list and fill out only the
        # sigScripts.
        totalScriptSize = 0
        if not isFull:
            count = wire.readVarInt(b, pver)

            # Prevent more input transactions than could possibly fit into a
            # message.  It would be possible to cause memory exhaustion and panics
            # without a sane upper bound on this count.
            if count > maxTxInPerMessage:
                raise Exception(
                    "MsgTx.decodeWitness: too many input transactions to fit into"
                    " max message size [count %d, max %d]" % (count, maxTxInPerMessage)
                )

            self.txIn = [TxIn(None, 0) for i in range(count)]
            for txIn in self.txIn:
                b = readTxInWitness(b, pver, self.version, txIn)
                totalScriptSize += len(txIn.signatureScript)
            self.txOut = []
        else:
            # We're decoding witnesses from a full transaction, so read in
            # the number of signature scripts, check to make sure it's the
            # same as the number of TxIns we currently have, then fill in
            # the signature scripts.
            count = wire.readVarInt(b, pver)

            if count != len(self.txIn):
                raise Exception(
                    "MsgTx.decodeWitness: non equal witness and prefix txin quantities"
                    " (witness %v, prefix %v)" % (count, len(self.txIn))
                )

            # Prevent more input transactions than could possibly fit into a
            # message.  It would be possible to cause memory exhaustion and panics
            # without a sane upper bound on this count.
            if count > maxTxInPerMessage:
                raise Exception(
                    "MsgTx.decodeWitness: too many input transactions to fit into"
                    " max message size [count %d, max %d]" % (count, maxTxInPerMessage)
                )

            # Read in the witnesses, and copy them into the already generated
            # by decodePrefix TxIns.
            if self.txIn is None or len(self.txIn) == 0:
                self.txIn = [
                    TxIn(None, 0) for i in range(count)
                ]  # := make([]TxIn, count)
            for txIn in self.txIn:
                b = readTxInWitness(b, pver, self.version, txIn)
                totalScriptSize += len(txIn.signatureScript)

        return b, totalScriptSize

    @staticmethod
    def btcDecode(b, pver):
        # r io.Reader, pver uint32) error {
        """
        BtcDecode decodes r using the Decred protocol encoding into the receiver.
        This is part of the Message interface implementation.
        See Deserialize for decoding transactions stored to disk, such as in a
        database, as opposed to decoding transactions from the wire.
        """
        # The serialized encoding of the version includes the real transaction
        # version in the lower 16 bits and the transaction serialization type
        # in the upper 16 bits.
        ver = b.pop(4).unLittle().int()

        tx = MsgTx.new()

        tx.version = ver & 0xFFFF
        tx.serType = ver >> 16

        # Serialize the transactions depending on their serialization
        # types.
        if tx.serType == wire.TxSerializeNoWitness:
            b, _ = tx.decodePrefix(b, pver)

        elif tx.serType == wire.TxSerializeOnlyWitness:
            b, _ = tx.decodeWitness(b, pver, False)

        elif tx.serType == wire.TxSerializeFull:
            b, _ = tx.decodePrefix(b, pver)
            b, _ = tx.decodeWitness(b, pver, True)

        else:
            raise Exception("MsgTx.BtcDecode: unsupported transaction type")

        return tx

    def serialize(self):
        return self.btcEncode(0)
    @staticmethod
    def deserialize(b):
        return MsgTx.btcDecode(b, 0)

    # blob and unblob satisfy the Blobber API from util.database
    @staticmethod
    def blob(msgTx):
        return msgTx.serialize().b
    @staticmethod
    def unblob(b):
        return MsgTx.btcDecode(b)

    def pkScriptLocs(self):  # []int {
        """
        PkScriptLocs returns a slice containing the start of each public key script
        within the raw serialized transaction.  The caller can easily obtain the
        length of each script by using len on the script available via the
        appropriate transaction output entry.
        TODO: Make this work for all serialization types, not just the full
        serialization type.
        """
        # Return nil for witness-only tx.
        numTxOut = len(self.txOut)
        if numTxOut == 0:
            return []

        # The starting offset in the serialized transaction of the first
        # transaction output is:

        # Version 4 bytes + serialized varint size for the number of
        # transaction inputs and outputs + serialized size of each transaction
        # input.
        n = (
            4
            + wire.varIntSerializeSize(len(self.txIn))
            + wire.varIntSerializeSize(numTxOut)
        )
        for txIn in self.txIn:
            n += txIn.serializeSizePrefix()

        # Calculate and set the appropriate offset for each public key script.
        pkScriptLocs = []
        for txOut in self.txOut:
            # The offset of the script in the transaction output is:

            # Value 8 bytes + version 2 bytes + serialized varint size
            # for the length of PkScript.
            n += 8 + 2 + wire.varIntSerializeSize(len(txOut.pkScript))
            pkScriptLocs.append(n)
            n += len(txOut.pkScript)
        return pkScriptLocs

    def looksLikeCoinbase(self):
        return self.txIn and self.txIn[0].previousOutPoint.hash.iszero()


# fmt: off

# multiTxPrefix is a MsgTx prefix with an input and output and used in various tests.
def multiTxPrefix():
    return MsgTx(
        cachedHash=None,
        serType=wire.TxSerializeNoWitness,
        version=1,
        txIn=[
            TxIn(
                previousOutPoint=OutPoint(
                    txHash=None,
                    idx=0xFFFFFFFF,
                    tree=TxTreeRegular,
                ),
                sequence=0xFFFFFFFF,
            ),
        ],
        txOut=[
            TxOut(
                value=0x12A05F200,
                version=0xABAB,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
            TxOut(
                value=0x5F5E100,
                version=0xBCBC,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
        ],
        lockTime=0,
        expiry=0,
    )


def multiTxPrefixEncoded():
    """
    multiTxPrefixEncoded is the wire encoded bytes for multiTx using protocol
    version 1 and is used in the various tests.
    """
    return ByteArray([
        0x01, 0x00, 0x01, 0x00, # Version [0]
        0x01,                           # Varint for number of input transactions [4]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # [5]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
        0XFF, 0XFF, 0XFF, 0XFF,         # Previous output index [37]
        0x00,                           # Previous output tree [41]
        0XFF, 0XFF, 0XFF, 0XFF,         # Sequence [43]
        0x02,                           # Varint for number of output transactions [47]
        0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, # Transaction amount [48]
        0xAB, 0xAB,                     # Script version
        0x43,                           # Varint for length of pk script [56]
        0x41,                           # OP_DATA_65 [57]
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                                           # 65-byte signature
        0xAC,                                           # OP_CHECKSIG
        0x00, 0xe1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount [124]
        0xBC, 0xBC,                     # Script version
        0x43,                           # Varint for length of pk script [132]
        0x41,                           # OP_DATA_65
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                           # 65-byte signature
        0xAC,                           # OP_CHECKSIG
        0x00, 0x00, 0x00, 0x00,         # Lock time [198]
        0x00, 0x00, 0x00, 0x00,         # Expiry [202]
    ])


multiTxPkScriptLocs = [58, 136]


def multiTxWitness():
    """
    multiTxWitness is a MsgTx witness with only input witness.
    """
    return MsgTx(
        cachedHash=None,
        serType=wire.TxSerializeOnlyWitness,
        version=1,
        txIn=[
            TxIn(
                previousOutPoint=None,
                sequence=0,
                valueIn=0x1212121212121212,
                blockHeight=0x15151515,
                blockIndex=0x34343434,
                signatureScript=ByteArray([
                    0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62
                ]),
            ),
        ],
        txOut=[],
        lockTime=0,
        expiry=0,
    )


def multiTxWitnessEncoded():
    return ByteArray([
        0x01, 0x00, 0x02, 0x00, # Version
        0x01,                           # Varint for number of input signature
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, # ValueIn
        0x15, 0x15, 0x15, 0x15,         # BlockHeight
        0x34, 0x34, 0x34, 0x34,         # BlockIndex
        0x07,                           # Varint for length of signature script
        0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62, # Signature script
    ])


def multiTx():
    """
    multiTx is a MsgTx with an input and output and used in various tests.
    """
    return MsgTx(
        cachedHash=None,
        serType=wire.TxSerializeFull,
        version=1,
        txIn=[
            TxIn(
                previousOutPoint=OutPoint(
                    txHash=None,
                    idx=0xFFFFFFFF,
                    tree=0,
                ),
                sequence=0xFFFFFFFF,
                valueIn=0x1212121212121212,
                blockHeight=0x15151515,
                blockIndex=0x34343434,
                signatureScript=ByteArray([
                    0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62
                ]),
            ),
        ],
        txOut=[
            TxOut(
                value=0x12A05F200,
                version=0xABAB,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
            TxOut(
                value=0x5F5E100,
                version=0xBCBC,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
        ],
        lockTime=0,
        expiry=0,
    )


def multiTxEncoded():
    """
    multiTxEncoded is the wire encoded bytes for multiTx using protocol version
    0 and is used in the various tests.
    """
    return ByteArray([
        0x01, 0x00, 0x00, 0x00, # Version [0]
        0x01,                           # Varint for number of input transactions [4]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # [5]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
        0XFF, 0XFF, 0XFF, 0XFF,         # Previous output index [37]
        0x00,                           # Previous output tree [41]
        0XFF, 0XFF, 0XFF, 0XFF,         # Sequence [42]
        0x02,                           # Varint for number of output transactions [46]
        0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, # Transaction amount [47]
        0xAB, 0xAB,                     # Script version [55]
        0x43,                           # Varint for length of pk script [57]
        0x41,                           # OP_DATA_65 [58]
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                                           # 65-byte pubkey
        0xAC,                                           # OP_CHECKSIG
        0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount [123]
        0xBC, 0xBC,                     # Script version [134]
        0x43,                           # Varint for length of pk script [136]
        0x41,                           # OP_DATA_65
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                           # 65-byte signature
        0xAC,                           # OP_CHECKSIG
        0x00, 0x00, 0x00, 0x00,         # Lock time [203]
        0x00, 0x00, 0x00, 0x00,         # Expiry [207]
        0x01,                           # Varint for number of input signature [211]
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, # ValueIn [212]
        0x15, 0x15, 0x15, 0x15,         # BlockHeight [220]
        0x34, 0x34, 0x34, 0x34,         # BlockIndex [224]
        0x07,                           # Varint for length of signature script [228]
        0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62, # Signature script [229]
    ])
