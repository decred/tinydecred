"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

Constants and common routines from the dcrd wire package.
"""
from tinydecred.crypto.bytearray import ByteArray

MaxInt8   = (1<<7) - 1
MinInt8   = -1 << 7
MaxInt16  = (1<<15) - 1
MinInt16  = -1 << 15
MaxInt32  = (1<<31) - 1
MinInt32  = -1 << 31
MaxInt64  = (1<<63) - 1
MinInt64  = -1 << 63
MaxUint8  = (1<<8) - 1
MaxUint16 = (1<<16) - 1
MaxUint32 = (1<<32) - 1
MaxUint64 = (1<<64) - 1

# Commands used in message headers which describe the type of message.
CmdVersion        = "version"
CmdVerAck         = "verack"
CmdGetAddr        = "getaddr"
CmdAddr           = "addr"
CmdGetBlocks      = "getblocks"
CmdInv            = "inv"
CmdGetData        = "getdata"
CmdNotFound       = "notfound"
CmdBlock          = "block"
CmdTx             = "tx"
CmdGetHeaders     = "getheaders"
CmdHeaders        = "headers"
CmdPing           = "ping"
CmdPong           = "pong"
CmdMemPool        = "mempool"
CmdMiningState    = "miningstate"
CmdGetMiningState = "getminings"
CmdReject         = "reject"
CmdSendHeaders    = "sendheaders"
CmdFeeFilter      = "feefilter"
CmdGetCFilter     = "getcfilter"
CmdGetCFHeaders   = "getcfheaders"
CmdGetCFTypes     = "getcftypes"
CmdCFilter        = "cfilter"
CmdCFHeaders      = "cfheaders"
CmdCFTypes        = "cftypes"

# MaxMessagePayload is the maximum bytes a message can be regardless of other
# individual limits imposed by messages themselves.
MaxMessagePayload = (1024 * 1024 * 32) # 32MB

# MaxBlockPayloadV3 is the maximum bytes a block message can be in bytes as of
# version 3 of the protocol.
MaxBlockPayloadV3 = 1000000 # Not actually 1MB which would be 1024 * 1024

# MaxBlockPayload is the maximum bytes a block message can be in bytes.
MaxBlockPayload = 1310720 # 1.25MB

# ProtocolVersion is the latest protocol version this package supports.
ProtocolVersion = 6

# TxTreeRegular is the value for a normal transaction tree for a
# transaction's location in a block.
TxTreeRegular = 0

# TxTreeStake is the value for a stake transaction tree for a
# transaction's location in a block.
TxTreeStake = 1

# Tx serialization types
# ----------------------
# TxSerializeFull indicates a transaction be serialized with the prefix
# and all witness data.
TxSerializeFull = 0
TxSerializeNoWitness = 1
# TxSerializeOnlyWitness indicates a transaction be serialized with
# only the witness data.
TxSerializeOnlyWitness = 2

# DefaultPkScriptVersion is the default pkScript version, referring to
# extended Decred script.
DefaultPkScriptVersion = 0x0000

def varIntSerializeSize(i):
    """
    The value is small enough to be represented by itself, so it's
    just 1 byte.
    """
    if i < 0xfd:
        return 1

    # Discriminant 1 byte plus 2 bytes for the uint16.
    if i <= MaxUint16:
        return 3

    # Discriminant 1 byte plus 4 bytes for the uint32.
    if i <= MaxUint32:
        return 5

    # Discriminant 1 byte plus 8 bytes for the uint64.
    return 9

def writeVarInt(pver, val):
    """
    writeVarInt serializes val to w using a variable number of bytes depending
    on its value.
    """

    if val < 0xfd:
        return ByteArray(val, length=1) # will be length 1

    if val <= MaxUint16:
        b = ByteArray(0xfd)
        b += ByteArray(val, length=2).littleEndian()
        return b

    if val <= MaxUint32:
        b = ByteArray(0xfe)
        b += ByteArray(val, length=4).littleEndian()
        return b

    b = ByteArray(0xff)
    b += ByteArray(val, length=8).littleEndian()
    return b

def writeVarBytes(pver, inBytes): #w io.Writer, pver uint32, bytes []byte) error {
    """
    writeVarBytes serializes a variable length byte array to w as a varInt
    containing the number of bytes, followed by the bytes themselves.
    """
    slen = len(inBytes)
    b = writeVarInt(pver, slen)
    b += inBytes
    return b

def readVarInt(b, pver): #r io.Reader, pver uint32) (uint64, error) {
    """
    readVarInt reads a variable length integer from r and returns it as a uint64.
    """
    discriminant = b.pop(1).int()
    rv = 0
    if discriminant == 0xff:
        rv = b.pop(8).unLittle().int()

        # The encoding is not canonical if the value could have been
        # encoded using fewer bytes.
        minRv = 0x100000000
        if rv < minRv:
            raise Exception("ReadVarInt noncanon error: %d - %d <= %d" % (rv, discriminant, minRv))
    elif discriminant == 0xfe:
        rv = b.pop(4).unLittle().int()

        # The encoding is not canonical if the value could have been
        # encoded using fewer bytes.
        minRv = 0x10000
        if rv < minRv:
            raise Exception("ReadVarInt noncanon error: %d - %d <= %d" % (rv, discriminant, minRv))

    elif discriminant == 0xfd:
        rv = b.pop(2).unLittle().int()

        # The encoding is not canonical if the value could have been
        # encoded using fewer bytes.
        minRv = 0xfd
        if rv < minRv:
            raise Exception("ReadVarInt noncanon error: %d - %d <= %d" % (rv, discriminant, minRv))

    else:
        rv = discriminant

    return rv
