"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

Based on dcrd MsgBlock.
"""
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.crypto.crypto import hashH

# chainhash.HashSize in go
HASH_SIZE = 32

MaxHeaderSize = 180

class BlockHeader:
    """
    BlockHeader defines information about a block and is used in the decred
    block (MsgBlock) and headers (MsgHeaders) messages.
    """
    def __init__(self):
        # Version of the block.  This is not the same as the protocol version.
        self.version = None # int32

        # Hash of the previous block in the block chain.
        self.prevBlock = None # chainhash.Hash = [32]byte

        # Merkle tree reference to hash of all transactions for the block.
        self.merkleRoot = None # chainhash.Hash

        # Merkle tree reference to hash of all stake transactions for the block.
        self.stakeRoot = None # chainhash.Hash

        # Votes on the previous merkleroot and yet undecided parameters.
        self.voteBits = None # uint16

        # Final state of the PRNG used for ticket selection in the lottery.
        self.finalState = None # [6]byte

        # Number of participating voters for this block.
        self.voters = None # uint16

        # Number of new sstx in this block.
        self.freshStake = None # uint8

        # Number of ssrtx present in this block.
        self.revocations = None # uint8

        # Size of the ticket pool.
        self.poolSize = None # uint32

        # Difficulty target for the block.
        self.bits = None # uint32

        # Stake difficulty target.
        self.sBits = None # int64

        # Height is the block height in the block chain.
        self.height = None # uint32

        # Size is the size of the serialized block in its entirety.
        self.size = None # uint32

        # Time the block was created.  This is, unfortunately, encoded as a
        # uint32 on the wire and therefore is limited to 2106.
        self.timestamp = None # time.Time

        # Nonce is technically a part of ExtraData, but we use it as the
        # classical 4-byte nonce here.
        self.nonce = None # uint32

        # ExtraData is used to encode the nonce or any other extra data
        # that might be used later on in consensus.
        self.extraData = None # [32]byte

        # StakeVersion used for voting.
        self.stakeVersion = None # uint32
    @staticmethod
    def deserialize(b):
        return BlockHeader.btcDecode(b, 0)
    @staticmethod
    def btcDecode(b, pver): # io.Reader, pver uint32) error {
        """
        BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
        This is part of the Message interface implementation.
        See Deserialize for decoding block headers stored to disk, such as in a
        database, as opposed to decoding block headers from the wire.
        """
        bh = BlockHeader()

        # byte sizes
        int64 = 8
        int32 = uint32 = 4
        uint16 = 2
        finalStateSize = 6
        uint8 = 1
        extraDataSize = 32

        # grab the data
        bh.version = b.pop(int32).unLittle().int() # int32
        bh.prevBlock = b.pop(HASH_SIZE) # chainhash.Hash = [32]byte
        bh.merkleRoot = b.pop(HASH_SIZE) # chainhash.Hash
        bh.stakeRoot = b.pop(HASH_SIZE) # chainhash.Hash
        bh.voteBits = b.pop(uint16).unLittle().int() # uint16
        bh.finalState = b.pop(finalStateSize) # [6]byte
        bh.voters = b.pop(uint16).unLittle().int() # uint16
        bh.freshStake = b.pop(uint8).unLittle().int() # uint8
        bh.revocations = b.pop(uint8).unLittle().int() # uint8
        bh.poolSize = b.pop(uint32).unLittle().int() # uint32
        bh.bits = b.pop(uint32).unLittle().int() # uint32
        bh.sBits = b.pop(int64).unLittle().int() # int64
        bh.height = b.pop(uint32).unLittle().int() # uint32
        bh.size = b.pop(uint32).unLittle().int() # uint32
        bh.timestamp = b.pop(uint32).unLittle().int() # uint32Time  # time.Time
        bh.nonce = b.pop(uint32).unLittle().int() # uint32
        bh.extraData = b.pop(extraDataSize) # [32]byte
        bh.stakeVersion = b.pop(uint32).unLittle().int() # uint32

        return bh
    def serialize(self):
        return self.btcEncode(0)
    def btcEncode(self,  pver):


    #     sec := uint32(bh.Timestamp.Unix())
    # return writeElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
    #     &bh.StakeRoot, bh.VoteBits, bh.FinalState, bh.Voters,
    #     bh.FreshStake, bh.Revocations, bh.PoolSize, bh.Bits, bh.SBits,
    #     bh.Height, bh.Size, sec, bh.Nonce, bh.ExtraData,
    #     bh.StakeVersion)

            # byte sizes
        int64 = 8
        int32 = uint32 = 4
        uint16 = 2
        finalStateSize = 6
        uint8 = 1
        extraDataSize = 32

        b = ByteArray(0, length=MaxHeaderSize)
        i = 0
        b[i] = ByteArray(self.version, length=int32).littleEndian()
        i += int32
        b[i] = ByteArray(self.prevBlock, length=HASH_SIZE)
        i += HASH_SIZE
        b[i] = ByteArray(self.merkleRoot, length=HASH_SIZE)
        i += HASH_SIZE
        b[i] = ByteArray(self.stakeRoot, length=HASH_SIZE)
        i += HASH_SIZE
        b[i] = ByteArray(self.voteBits, length=uint16).littleEndian()
        i += uint16
        b[i] = ByteArray(self.finalState, length=finalStateSize)
        i += finalStateSize
        b[i] = ByteArray(self.voters, length=uint16).littleEndian()
        i += uint16
        b[i] = ByteArray(self.freshStake, length=uint8).littleEndian()
        i += uint8
        b[i] = ByteArray(self.revocations, length=uint8).littleEndian()
        i += uint8
        b[i] = ByteArray(self.poolSize, length=uint32).littleEndian()
        i += uint32
        b[i] = ByteArray(self.bits, length=uint32).littleEndian()
        i += uint32
        b[i] = ByteArray(self.sBits, length=int64).littleEndian()
        i += int64
        b[i] = ByteArray(self.height, length=uint32).littleEndian()
        i += uint32
        b[i] = ByteArray(self.size, length=uint32).littleEndian()
        i += uint32
        b[i] = ByteArray(self.timestamp, length=uint32).littleEndian()
        i += uint32
        b[i] = ByteArray(self.nonce, length=uint32).littleEndian()
        i += uint32
        b[i] = ByteArray(self.extraData, length=extraDataSize)
        i += extraDataSize
        b[i] = ByteArray(self.stakeVersion, length=uint32).littleEndian()
        i += uint32
        if i != MaxHeaderSize:
            raise Exception("unexpected BlockHeader enocoded size")
        return b
    def hash(self): # chainhash.Hash {
        """
        hash computes the block identifier hash for the given block header.
        """
        # Encode the header and hash256 everything prior to the number of
        # transactions.  Ignore the error returns since there is no way the
        # encode could fail except being out of memory which would cause a
        # run-time panic.
        return hashH(self.serialize().bytes())
    def id(self):
        return reversed(self.hash()).hex()
