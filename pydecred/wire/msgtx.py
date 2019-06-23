"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

Based on dcrd MsgTx.
"""
import unittest
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.crypto.crypto import hashH
from tinydecred.util import helpers
from tinydecred.pydecred.wire import wire


# TxVersion is the current latest supported transaction version.
TxVersion = 1 # go type uint16

# TxTreeRegular is the value for a normal transaction tree for a
# transaction's location in a block.
TxTreeRegular = 0 # go type int8

# TxTreeStake is the value for a stake transaction tree for a
# transaction's location in a block.
TxTreeStake = 1 # go type int8

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
MaxTxInSequenceNum = 0xffffffff


def writeOutPoint(pver, ver, op): #w io.Writer, pver uint32, version uint16, op *OutPoint) error {
    """
    writeOutPoint encodes op to the Decred protocol encoding for an OutPoint
    to w.
    """
    b = op.hash.copy()
    b += ByteArray(op.index, length=4).littleEndian()
    b += ByteArray(op.tree, length=1)
    return b


def readOutPoint(b, pver, ver): #r io.Reader, pver uint32, version uint16, op *OutPoint) error {
    """ readOutPoint reads the next sequence of bytes from r as an OutPoint."""
    op = OutPoint(None, None, None)
    op.hash = b.pop(HASH_SIZE)
    op.index = b.pop(4).unLittle().int()
    op.tree = b.pop(1).int()
    return b, op

def readTxInPrefix(b, pver, serType, ver, ti): # r io.Reader, pver uint32, serType TxSerializeType, version uint16, ti *TxIn) error {
    if serType == wire.TxSerializeOnlyWitness:
        raise Exception("readTxInPrefix: tried to read a prefix input for a witness only tx")

    # Outpoint.
    b, ti.previousOutPoint = readOutPoint(b, pver, ver)

    # Sequence.
    ti.sequence = b.pop(4).unLittle().int()

def writeTxInPrefix(pver, ver, ti): #pver uint32, version uint16, ti *TxIn) error {
    """
    writeTxInPrefixs encodes ti to the Decred protocol encoding for a transaction
    input (TxIn) prefix to w.
    """
    b = writeOutPoint(pver, ver, ti.previousOutPoint)
    b += ByteArray(ti.sequence, length=4).littleEndian()
    return b

def writeTxInWitness(pver, ver, ti): #w io.Writer, pver uint32, version uint16, ti *TxIn) error {
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

def readScript(b, pver, maxAllowed, fieldName): # r io.Reader, pver uint32, maxAllowed uint32, fieldName string) ([]byte, error) {
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
        raise Exception("readScript: %s is larger than the max allowed size [count %d, max %d]" % (fieldName, count, maxAllowed))

    a = b.pop(count)

    return b, a

def readTxInWitness(b, pver, ver, ti): # r io.Reader, pver uint32, version uint16, ti *TxIn) error {
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
    b, ti.signatureScript = readScript(b, pver, wire.MaxMessagePayload, "transaction input signature script")

    return b

def readTxOut(b, pver, ver, to): # r io.Reader, pver uint32, version uint16, to *TxOut) error {
    """
    # readTxOut reads the next sequence of bytes from r as a transaction output (TxOut).
    """
    to.value = b.pop(8).unLittle().int()
    to.version = b.pop(2).unLittle().int()
    b, to.pkScript = readScript(b, pver, wire.MaxMessagePayload, "transaction output public key script")
    return b

def writeTxOut(pver, ver, to): # w io.Writer, pver uint32, version uint16, to *TxOut) error {
    """
    writeTxOut encodes to into the Decred protocol encoding for a transaction
    output (TxOut) to w.
    """
    b = ByteArray(to.value, length=8).littleEndian()
    b += ByteArray(to.version, length=2).littleEndian()
    b += wire.writeVarBytes(pver, to.pkScript)
    return b

# def writeTxScriptsToMsgTx(msg, totalScriptSize, serType): # msg *MsgTx, totalScriptSize uint64, serType TxSerializeType) {
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
    def __init__(self, previousOutPoint, sequence=MaxTxInSequenceNum, valueIn=0, blockHeight=0, blockIndex=0, signatureScript=None):
        # Non-witness
        self.previousOutPoint = previousOutPoint # OutPoint
        self.sequence = sequence # uint32

        # Witness
        self.valueIn = valueIn # int64
        self.blockHeight = blockHeight # uint32
        self.blockIndex = blockIndex # uint32
        self.signatureScript = signatureScript if signatureScript else ByteArray(b'') # []byte
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
        return 8 + 4 + 4 + wire.varIntSerializeSize(len(self.signatureScript)) + len(self.signatureScript)
    def __eq__(self, ti):
        """
        Check whether all fields are equal
        """
        a = (
            self.previousOutPoint == ti.previousOutPoint and
            self.sequence == ti.sequence and
            self.valueIn == ti.valueIn and
            self.blockHeight == ti.blockHeight and
            self.blockIndex == ti.blockIndex and
            self.signatureScript == ti.signatureScript
        )
        return a


class TxOut:
    """
    TxOut defines a Decred transaction output.
    """
    def __init__(self, value=0, pkScript=None, version=0):
        self.value = value # int64
        self.version = version # uint16
        self.pkScript = pkScript if pkScript else ByteArray(b'') # []byte
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
        return(
            self.value == to.value and
            self.version == to.version and
            self.pkScript == to.pkScript
        )

class OutPoint:
    """
    OutPoint defines a Decred data type that is used to track previous
    transaction outputs.
    """
    def __init__(self, txHash, idx, tree):
        self.hash = txHash if txHash else ByteArray(0, length=HASH_SIZE) # chainhash.Hash
        self.index = idx # uint32
        self.tree = tree # int8
    def __eq__(self, other):
        return (
            self.hash == other.hash and
            self.index == other.index and
            self.tree == other.tree
        )
    def hashString(self):
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
        """ Return a fully serialized version 1 transaction. Python equivalent of NewMsgTx in go."""
        return MsgTx(
            cachedHash = None,
            serType = wire.TxSerializeFull,
            version = TxVersion,
            txIn = [],
            txOut = [],
            lockTime = 0,
            expiry = 0,
        )
    def __eq__(self, tx):
        """ Check equality of all fields. Useful in testing"""
        return (
            self.cachedHash == tx.cachedHash and
            self.serType == tx.serType and
            self.version == tx.version and
            all((a == b for a, b in zip(self.txIn, tx.txIn))) and
            all((a == b for a, b in zip(self.txOut, tx.txOut))) and
            self.lockTime == tx.lockTime and
            self.expiry == tx.expiry
        )
    def addTxIn(self, tx):
        self.txIn.append(tx)
    def addTxOut(self, tx):
        self.txOut.append(tx)
    def txHash(self): # chainhash.Hash {
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
        return self.serialize().hex()
    def txid(self):
        """ hex encoded, byte-reversed tx hash """
        return reversed(self.txHash()).hex()
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
        """ encodePrefix encodes a transaction prefix into a writer."""
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
    def encodeWitness(self, pver): #w io.Writer, pver uint32) error {
        """ encodeWitness encodes a transaction witness into a writer."""
        count = len(self.txIn)
        b = wire.writeVarInt(pver, count)

        for ti in self.txIn:
            b += writeTxInWitness(pver, self.version, ti)

        return b
    def btcEncode(self, pver): #w io.Writer, pver uint32) error {
        """
        BtcEncode encodes the receiver to w using the Decred protocol encoding.
        This is part of the Message interface implementation.
        See Serialize for encoding transactions to be stored to disk, such as in a
        database, as opposed to encoding transactions for the wire.
        """
        # The serialized encoding of the version includes the real transaction
        # version in the lower 16 bits and the transaction serialization type
        # in the upper 16 bits.
        b = ByteArray(self.version | (self.serType<<16), length=4).littleEndian()

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
            n = 12 + wire.varIntSerializeSize(len(self.txIn)) + wire.varIntSerializeSize(len(self.txOut))

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
            n = 12 + wire.varIntSerializeSize(len(self.txIn)) +  wire.varIntSerializeSize(len(self.txIn)) + wire.varIntSerializeSize(len(self.txOut))

            for txIn in self.txIn:
                n += txIn.serializeSizePrefix()
            for txIn in self.txIn:
                n += txIn.serializeSizeWitness()
            for txOut in self.txOut:
                n += txOut.serializeSize()
        return n
    def serialize(self):
        return self.btcEncode(0)
    def decodePrefix(self, b, pver): # r io.Reader, pver uint32) (uint64, error) {
        """
        decodePrefix decodes a transaction prefix and stores the contents
        in the embedded msgTx.
        """
        count = wire.readVarInt(b, pver)
        # Prevent more input transactions than could possibly fit into a
        # message.  It would be possible to cause memory exhaustion and panics
        # without a sane upper bound on this count.
        if count > maxTxInPerMessage:
            raise Exception("too many input transactions to fit into  max message size [count %d, max %d]" % (count, maxTxInPerMessage))

        # TxIns.
        txIns = self.txIn = [TxIn(None, 0) for i in range(count)] 
        for txIn in txIns:
            readTxInPrefix(b, pver, self.serType, self.version, txIn)

        count = wire.readVarInt(b, pver)

        # Prevent more output transactions than could possibly fit into a
        # message.  It would be possible to cause memory exhaustion and panics
        # without a sane upper bound on this count.
        if count > maxTxOutPerMessage:
            raise Exception("MsgTx.decodePrefixtoo many output transactions to fit into  max message size [count %d, max %d]" % (count, maxTxOutPerMessage))

        # TxOuts.
        totalScriptSize = 0
        txOuts = self.txOut =  [TxOut(None, None) for i in range(count)]
        for txOut in txOuts:
            # The pointer is set now in case a script buffer is borrowed
            # and needs to be returned to the pool on error.
            b = readTxOut(b, pver, self.version, txOut)
            totalScriptSize += len(txOut.pkScript)

        # Locktime and expiry.
        self.lockTime = b.pop(4).unLittle().int()

        self.expiry = b.pop(4).unLittle().int()
        return b, totalScriptSize
    def decodeWitness(self, b, pver, isFull): # r io.Reader, pver uint32, isFull bool) (uint64, error) {
        # Witness only; generate the TxIn list and fill out only the
        # sigScripts.
        totalScriptSize = 0
        if not isFull:
            count = wire.readVarInt(b, pver)

            # Prevent more input transactions than could possibly fit into a
            # message.  It would be possible to cause memory exhaustion and panics
            # without a sane upper bound on this count.
            if count > maxTxInPerMessage:
                raise Exception("MsgTx.decodeWitness: too many input transactions to fit into max message size [count %d, max %d]" % (count, maxTxInPerMessage))

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
                raise Exception("MsgTx.decodeWitness: non equal witness and prefix txin quantities (witness %v, prefix %v)" % (count, len(self.txIn)))

            # Prevent more input transactions than could possibly fit into a
            # message.  It would be possible to cause memory exhaustion and panics
            # without a sane upper bound on this count.
            if count > maxTxInPerMessage:
                raise Exception("MsgTx.decodeWitness: too many input transactions to fit into max message size [count %d, max %d]" % (count, maxTxInPerMessage))

            # Read in the witnesses, and copy them into the already generated
            # by decodePrefix TxIns.
            if self.txIn is None or len(self.txIn) == 0:
                self.txIn = [TxIn(None, 0) for i in range(count)]  # := make([]TxIn, count)
            for txIn in self.txIn:
                b = readTxInWitness(b, pver, self.version, txIn)
                totalScriptSize += len(txIn.signatureScript)

        return b, totalScriptSize
    @staticmethod
    def btcDecode(b, pver): #r io.Reader, pver uint32) error {
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


        tx.version = ver & 0xffff
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
    @staticmethod
    def deserialize(b):
        return MsgTx.btcDecode(b, 0)
    def pkScriptLocs(self): # []int {
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
        n = 4 + wire.varIntSerializeSize(len(self.txIn)) + wire.varIntSerializeSize(numTxOut)
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

# multiTxPrefix is a MsgTx prefix with an input and output and used in various tests.
def multiTxPrefix():
    return MsgTx(
        cachedHash = None,
        serType = wire.TxSerializeNoWitness,
        version = 1,
        txIn = [
            TxIn(
                previousOutPoint = OutPoint(
                    txHash = None,
                    idx = 0xffffffff,
                    tree = TxTreeRegular,
                ),
                sequence = 0xffffffff,
            ),
        ],
        txOut = [
            TxOut(
                value = 0x12a05f200,
                version = 0xabab,
                pkScript = ByteArray([
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6, # 65-byte signature
                    0xac, # OP_CHECKSIG
                ]),
            ),
            TxOut(
                value =   0x5f5e100,
                version = 0xbcbc,
                pkScript = ByteArray([
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6, # 65-byte signature
                    0xac, # OP_CHECKSIG
                ]),
            ),
        ],
        lockTime = 0,
        expiry = 0,
    )

def multiTxPrefixEncoded():
    """
    multiTxPrefixEncoded is the wire encoded bytes for multiTx using protocol
    version 1 and is used in the various tests.
    """
    return ByteArray([
        0x01, 0x00, 0x01, 0x00, # Version [0]
        0x01,                                           # Varint for number of input transactions [4]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # [5]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
        0xff, 0xff, 0xff, 0xff, # Previous output index [37]
        0x00,                   # Previous output tree [41]
        0xff, 0xff, 0xff, 0xff, # Sequence [43]
        0x02,                                           # Varint for number of output transactions [47]
        0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, # Transaction amount [48]
        0xab, 0xab, # Script version
        0x43, # Varint for length of pk script [56]
        0x41, # OP_DATA_65 [57]
        0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
        0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
        0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
        0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
        0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
        0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
        0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
        0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
        0xa6,                                           # 65-byte signature
        0xac,                                           # OP_CHECKSIG
        0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount [124]
        0xbc, 0xbc, # Script version
        0x43, # Varint for length of pk script [132]
        0x41, # OP_DATA_65
        0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
        0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
        0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
        0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
        0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
        0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
        0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
        0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
        0xa6,                   # 65-byte signature
        0xac,                   # OP_CHECKSIG
        0x00, 0x00, 0x00, 0x00, # Lock time [198]
        0x00, 0x00, 0x00, 0x00, # Expiry [202]
    ])

multiTxPkScriptLocs = [58, 136]

def multiTxWitness():
    """
    multiTxWitness is a MsgTx witness with only input witness.
    """
    return MsgTx(
        cachedHash = None,
        serType = wire.TxSerializeOnlyWitness,
        version = 1,
        txIn = [
            TxIn(
                previousOutPoint = None,
                sequence = 0,
                valueIn =     0x1212121212121212,
                blockHeight = 0x15151515,
                blockIndex =  0x34343434,
                signatureScript = ByteArray([
                    0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62,
                ]),
            ),
        ],
        txOut = [],
        lockTime = 0, 
        expiry = 0,
    )

def multiTxWitnessEncoded():
    return ByteArray([
        0x01, 0x00, 0x02, 0x00, # Version
        0x01,                                           # Varint for number of input signature
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, # ValueIn
        0x15, 0x15, 0x15, 0x15, # BlockHeight
        0x34, 0x34, 0x34, 0x34, # BlockIndex
        0x07,                                     # Varint for length of signature script
        0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62, # Signature script
    ])

def multiTx():
    """ multiTx is a MsgTx with an input and output and used in various tests."""
    return MsgTx(
        cachedHash = None,
        serType = wire.TxSerializeFull,
        version = 1,
        txIn = [
            TxIn(
                previousOutPoint = OutPoint(
                    txHash = None,
                    idx = 0xffffffff,
                    tree = 0,
                ),
                sequence =    0xffffffff,
                valueIn =     0x1212121212121212,
                blockHeight = 0x15151515,
                blockIndex =  0x34343434,
                signatureScript = ByteArray([
                    0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62,
                ]),
            ),
        ],
        txOut = [
            TxOut(
                value =   0x12a05f200,
                version = 0xabab,
                pkScript = ByteArray([
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6, # 65-byte signature
                    0xac, # OP_CHECKSIG
                ]),
            ),
            TxOut(
                value =   0x5f5e100,
                version = 0xbcbc,
                pkScript = ByteArray([
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6, # 65-byte signature
                    0xac, # OP_CHECKSIG
                ]),
            ),
        ],
        lockTime = 0,
        expiry =   0,
    )

def multiTxEncoded():
    """
    multiTxEncoded is the wire encoded bytes for multiTx using protocol version
    0 and is used in the various tests.
    """
    return ByteArray([
        0x01, 0x00, 0x00, 0x00, # Version [0]
        0x01,                                           # Varint for number of input transactions [4]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # [5]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
        0xff, 0xff, 0xff, 0xff, # Previous output index [37]
        0x00,                   # Previous output tree [41]
        0xff, 0xff, 0xff, 0xff, # Sequence [42]
        0x02,                                           # Varint for number of output transactions [46]
        0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, # Transaction amount [47]
        0xab, 0xab, # Script version [55]
        0x43, # Varint for length of pk script [57]
        0x41, # OP_DATA_65 [58]
        0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
        0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
        0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
        0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
        0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
        0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
        0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
        0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
        0xa6,                                           # 65-byte pubkey
        0xac,                                           # OP_CHECKSIG
        0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount [123]
        0xbc, 0xbc, # Script version [134]
        0x43, # Varint for length of pk script [136]
        0x41, # OP_DATA_65
        0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
        0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
        0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
        0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
        0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
        0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
        0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
        0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
        0xa6,                   # 65-byte signature
        0xac,                   # OP_CHECKSIG
        0x00, 0x00, 0x00, 0x00, # Lock time [203]
        0x00, 0x00, 0x00, 0x00, # Expiry [207]
        0x01,                                           # Varint for number of input signature [211]
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, # ValueIn [212]
        0x15, 0x15, 0x15, 0x15, # BlockHeight [220]
        0x34, 0x34, 0x34, 0x34, # BlockIndex [224]
        0x07,                                     # Varint for length of signature script [228]
        0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62, # Signature script [229]
    ])

class TestMsgTx(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.prepareLogger("TestMsgTx")
    def test_tx_serialize_size(self):
        """
        TestTxSerializeSize performs tests to ensure the serialize size for various
        transactions is accurate.
        """
        # Empty tx message.
        noTx = MsgTx.new()
        noTx.version = 1

        tests = [
            # No inputs or outpus.
            (noTx, 15),
            # Transaction with an input and an output.
            (multiTx(), 236),
        ]

        for i, (txIn, size) in enumerate(tests):
            self.assertEqual(txIn.serializeSize(), size)
    def test_tx_hash(self):
        """ TestTxHash tests the ability to generate the hash of a transaction accurately. """
        # Hash of first transaction from block 113875.
        wantHash = reversed(ByteArray("4538fc1618badd058ee88fd020984451024858796be0a1ed111877f887e1bd53"))

        msgTx = MsgTx.new()
        txIn = TxIn(
            previousOutPoint = OutPoint(
                txHash =  None,
                idx = 0xffffffff,
                tree =  TxTreeRegular,
            ),
            sequence =        0xffffffff,
            valueIn =         5000000000,
            blockHeight =     0x3F3F3F3F,
            blockIndex =      0x2E2E2E2E,
            signatureScript = ByteArray([0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62]),
        )
        txOut = TxOut(
            value =   5000000000,
            version = 0xf0f0,
            pkScript = ByteArray([
                0x41, # OP_DATA_65
                0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                0xa6, # 65-byte signature
                0xac, # OP_CHECKSIG
            ]),
        )
        msgTx.addTxIn(txIn)
        msgTx.addTxOut(txOut)
        msgTx.lockTime = 0
        msgTx.expiry = 0
        # Ensure the hash produced is expected.
        self.assertEqual(msgTx.txHash(), wantHash)
            
    def test_tx_serialize_prefix(self):
        """
        TestTxSerializePrefix tests MsgTx serialize and deserialize.
        """
        noTx = MsgTx.new()
        noTx.version = 1
        noTx.serType = wire.TxSerializeNoWitness
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x01, 0x00, # Version
            0x00,                   # Varint for number of input transactions
            0x00,                   # Varint for number of output transactions
            0x00, 0x00, 0x00, 0x00, # Lock time
            0x00, 0x00, 0x00, 0x00, # Expiry
        ])

        mtPrefix = multiTxPrefix()
        tests = [
            # No transactions.
            (
                noTx,        # in           *MsgTx  Message to encode
                noTx,        # out          *MsgTx  Expected decoded message
                noTxEncoded, # buf          []byte  Serialized data
                [],        # pkScriptLocs []int   Expected output script locations
            ),
            # Multiple transactions.
            (
                mtPrefix,
                mtPrefix,
                multiTxPrefixEncoded(),
                multiTxPkScriptLocs,
            ),
        ]

        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            self.assertEqual(len(buf), inTx.serializeSize())
            self.assertEqual(buf, testBuf)
            
            # Deserialize the transaction.
            tx = MsgTx.deserialize(testBuf.copy())

            self.assertEqual(tx, out)

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()

            if pkScriptLocs is None:
                self.assertEqual(psl, pkScriptLocs)
            else:
                self.assertListEqual(psl, pkScriptLocs)
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.txOut[j].pkScript
                    gotPkScript = testBuf[loc : loc+len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript)
    def test_tx_serialize_witness(self):
        """ TestTxSerializeWitness tests MsgTx serialize and deserialize."""
        noTx = MsgTx.new()
        noTx.serType = wire.TxSerializeOnlyWitness
        noTx.version = 1
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x02, 0x00, # Version
            0x00, # Varint for number of input signatures
        ])
        # in           *MsgTx // Message to encode
        # out          *MsgTx // Expected decoded message
        # buf          []byte // Serialized data
        # pkScriptLocs []int  // Expected output script locations
        tests = [
            # No transactions.
            [
                noTx,
                noTx,
                noTxEncoded,
                [],
            ],

            # Multiple transactions.
            [
                multiTxWitness(),
                multiTxWitness(),
                multiTxWitnessEncoded(),
                [],
            ],
        ]
        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            self.assertEqual(len(buf), inTx.serializeSize())
            self.assertEqual(buf, testBuf)

            # Deserialize the transaction.
            tx = MsgTx.deserialize(testBuf.copy())
            self.assertEqual(tx, out)

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()
            if pkScriptLocs is None:
                self.assertEqual(psl, pkScriptLocs)
            else:
                self.assertListEqual(psl, pkScriptLocs)
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.TxIn[j].pkScript
                    gotPkScript = testBuf[loc : loc+len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript)
    def test_tx_serialize(self):
        """ TestTxSerialize tests MsgTx serialize and deserialize. """
        noTx = MsgTx.new()
        noTx.version = 1
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x00, 0x00, # Version
            0x00,                   # Varint for number of input transactions
            0x00,                   # Varint for number of output transactions
            0x00, 0x00, 0x00, 0x00, # Lock time
            0x00, 0x00, 0x00, 0x00, # Expiry
            0x00, # Varint for number of input signatures
        ])
        # in           *MsgTx // Message to encode
        # out          *MsgTx // Expected decoded message
        # buf          []byte // Serialized data
        # pkScriptLocs []int  // Expected output script locations
        tests = [
            # No transactions.
            [
                noTx,
                noTx,
                noTxEncoded,
                [],
            ],

            # Multiple transactions.
            [
                multiTx(),
                multiTx(),
                multiTxEncoded(),
                multiTxPkScriptLocs,
            ],
        ]

        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            self.assertEqual(len(buf), inTx.serializeSize(), msg="buflen %i" % i)
            self.assertEqual(buf, testBuf, msg="buf contents %i" % i)

            # Deserialize the transaction.
            tx = MsgTx.deserialize(testBuf.copy())

            self.assertEqual(tx, out, msg="txs %i" % i)

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()
            if pkScriptLocs is None:
                self.assertEqual(psl, pkScriptLocs, msg="psl none %i" % i)
            else:
                self.assertListEqual(psl, pkScriptLocs, msg="psl %i" % i)
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.txOut[j].pkScript
                    gotPkScript = testBuf[loc : loc+len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript, msg="scripts %i" % i)
    def test_tx_overflow_errors(self):
        """
        TestTxOverflowErrors performs tests to ensure deserializing transactions
        which are intentionally crafted to use large values for the variable number
        of inputs and outputs are handled properly.  This could otherwise potentially
        be used as an attack vector.
        """
        # Use protocol version 1 and transaction version 1 specifically
        # here instead of the latest values because the test data is using
        # bytes encoded with those versions.
        pver = 1
        txVer = 1
            # buf     []byte // Wire encoding
            # pver    uint32 // Protocol version for wire encoding
            # version int32  // Transaction version
            # err     error  // Expected error
        tests = [
            # Transaction that claims to have ~uint64(0) inputs. [0]
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, # Varint for number of input transactions
                ]), pver, txVer,
            ),

            # Transaction that claims to have ~uint64(0) outputs. [1]
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0x00, # Varint for number of input transactions
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, # Varint for number of output transactions
                ]), pver, txVer,
            ),

            # Transaction that has an input with a signature script that [2]
            # claims to have ~uint64(0) length.
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0x01, # Varint for number of input transactions
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
                    0xff, 0xff, 0xff, 0xff, # Previous output index
                    0x00,                   # Previous output tree
                    0x00,                   # Varint for length of signature script
                    0xff, 0xff, 0xff, 0xff, # Sequence
                    0x02,                                           # Varint for number of output transactions
                    0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, # Transaction amount
                    0x43, # Varint for length of pk script
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6,                                           # 65-byte signature
                    0xac,                                           # OP_CHECKSIG
                    0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount
                    0x43, # Varint for length of pk script
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6,                   # 65-byte signature
                    0xac,                   # OP_CHECKSIG
                    0x00, 0x00, 0x00, 0x00, # Lock time
                    0x00, 0x00, 0x00, 0x00, # Expiry
                    0x01,                                                 # Varint for number of input signature
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, # Varint for sig script length (overflows)
                ]), pver, txVer,
            ),

            # Transaction that has an output with a public key script [3]
            # that claims to have ~uint64(0) length.
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0x01, # Varint for number of input transactions
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
                    0xff, 0xff, 0xff, 0xff, # Prevous output index
                    0x00,                   # Previous output tree
                    0x00,                   # Varint for length of signature script
                    0xff, 0xff, 0xff, 0xff, # Sequence
                    0x01,                                           # Varint for number of output transactions
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Transaction amount
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, # Varint for length of public key script
                ]), pver, txVer,
            ),
        ]

        for i, (buf, pver, version) in enumerate(tests):
            # Decode from wire format.
            with self.assertRaises(Exception, msg="test %i" % i):
                MsgTx.btcDecode(buf, pver)
    def  test_tx_serialize_errors(self): # TestTxSerializeErrors(t *testing.T) {
        """
        TestTxSerializeErrors performs negative tests against wire encode and decode
        of MsgTx to confirm error paths work correctly.
        """
        # in       *MsgTx // Value to encode
        # buf      []byte // Serialized data
        # max      int    // Max size of fixed buffer to induce errors
        # writeErr error  // Expected write error
        # readErr  error  // Expected read error
        test = [
            # Force error in version.
            (multiTx, multiTxEncoded, 0),
            # Force error in number of transaction inputs.
            (multiTx, multiTxEncoded, 4),
            # Force error in transaction input previous block hash.
            (multiTx, multiTxEncoded, 5),
            # Force error in transaction input previous block output index.
            (multiTx, multiTxEncoded, 37),
            # Force error in transaction input previous block output tree.
            (multiTx, multiTxEncoded, 41),
            # Force error in transaction input sequence.
            (multiTx, multiTxEncoded, 42),
            # Force error in number of transaction outputs.
            (multiTx, multiTxEncoded, 46),
            # Force error in transaction output value.
            (multiTx, multiTxEncoded, 47),
            # Force error in transaction output version.
            (multiTx, multiTxEncoded, 55),
            # Force error in transaction output pk script length.
            (multiTx, multiTxEncoded, 57),
            # Force error in transaction output pk script.
            (multiTx, multiTxEncoded, 58),
            # Force error in transaction lock time.
            (multiTx, multiTxEncoded, 203),
            # Force error in transaction expiry.
            (multiTx, multiTxEncoded, 207),
            # Force error in transaction num sig varint.
            (multiTx, multiTxEncoded, 211),
            # Force error in transaction sig 0 ValueIn.
            (multiTx, multiTxEncoded, 212),
            # Force error in transaction sig 0 BlockHeight.
            (multiTx, multiTxEncoded, 220),
            # Force error in transaction sig 0 BlockIndex.
            (multiTx, multiTxEncoded, 224),
            # Force error in transaction sig 0 length.
            (multiTx, multiTxEncoded, 228),
            # Force error in transaction sig 0 signature script.
            (multiTx, multiTxEncoded, 229),
        ]
        # TO DO: Re-implement this test?
        # for i, (inTx, txBuf, mx) in enumerate(tests):
        #   # Serialize the transaction.
        #   w := newFixedWriter(test.max)
        #   err := test.in.Serialize(w)
        #   if err != test.writeErr {
        #       t.Errorf("Serialize #%d wrong error got: %v, want: %v",
        #           i, err, test.writeErr)
        #       continue
        #   }

        #   # Deserialize the transaction.
        #   var tx MsgTx
        #   r := newFixedReader(test.max, test.buf)
        #   err = tx.Deserialize(r)
        #   if err != test.readErr {
        #       t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
        #           i, err, test.readErr)
        #       continue
    def test_tx(self):
        """
        TestTx tests the MsgTx API.
        This test is substantially truncated compare to it's counterpart in go
        """
        # Ensure the command is expected value.
        wantCmd = "tx"
        msg = MsgTx.new()
        self.assertEqual(msg.command(), wantCmd)

        # Ensure max payload is expected value for latest protocol version.
        # Num addresses (varInt) + max allowed addresses.
        wantPayload = 1310720
        maxPayload = msg.maxPayloadLength(wire.ProtocolVersion)
        self.assertEqual(maxPayload, wantPayload)

        # Ensure max payload is expected value for protocol version 3.
        wantPayload = 1000000
        maxPayload = msg.maxPayloadLength(3)
        self.assertEqual(wantPayload, maxPayload)
    def test_tx_from_hex(self):
        pver = 1
        hexTx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0300f2052a01000000000017a914cbb08d6ca783b533b2c7d24a51fbca92d937bf9987000000000000000000000e6a0c1b000000b1bf47057791232500ac23fc0600000000001976a914b1eef3d1535a3868d11fa297c35f3deba978036088ac000000000000000001009e29260800000000000000ffffffff0800002f646372642f"
        buf = ByteArray(hexTx)
        tx = MsgTx.btcDecode(buf, pver)
        print(repr(tx.cachedHash))
        print(repr(tx.serType))
        print(repr(tx.version))
        print(repr(tx.txIn))
        print(repr(tx.txOut))
        print(repr(tx.lockTime))
        print(repr(tx.expiry))
        v = sum(txout.value for txout in tx.txOut)
        print("--total sent: %.2f" % (v*1e-8,))
        print(tx.txHex())
