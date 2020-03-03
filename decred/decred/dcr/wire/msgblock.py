"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details

Based on dcrd MsgBlock.
"""

from decred.crypto import crypto
from decred.util.encode import ByteArray


# chainhash.HashSize in Go
HASH_SIZE = 32

MaxHeaderSize = 180


class BlockHeader:
    """
    BlockHeader defines information about a block and is used in the decred
    block (MsgBlock) and headers (MsgHeaders) messages.
    """

    def __init__(self):
        # version of the block.  This is not the same as the protocol version.
        self.version = None  # int32

        # hash of the previous block in the block chain.
        self.prevBlock = None  # chainhash.Hash = [32]byte

        # merkle tree reference to hash of all transactions for the block.
        self.merkleRoot = None  # chainhash.Hash

        # merkle tree reference to hash of all stake transactions for the block.
        self.stakeRoot = None  # chainhash.Hash

        # votes on the previous merkleroot and yet undecided parameters.
        self.voteBits = None  # uint16

        # final state of the PRNG used for ticket selection in the lottery.
        self.finalState = None  # [6]byte

        # number of participating voters for this block.
        self.voters = None  # uint16

        # number of new sstx in this block.
        self.freshStake = None  # uint8

        # number of ssrtx present in this block.
        self.revocations = None  # uint8

        # size of the ticket pool.
        self.poolSize = None  # uint32

        # difficulty target for the block.
        self.bits = None  # uint32

        # stake difficulty target.
        self.sBits = None  # int64

        # height is the block height in the block chain.
        self.height = None  # uint32

        # size is the size of the serialized block in its entirety.
        self.size = None  # uint32

        # time the block was created.  This is, unfortunately, encoded as a
        # uint32 on the wire and therefore is limited to 2106.
        self.timestamp = None  # time.Time

        # nonce is technically a part of ExtraData, but we use it as the
        # classical 4-byte nonce here.
        self.nonce = None  # uint32

        # extraData is used to encode the nonce or any other extra data
        # that might be used later on in consensus.
        self.extraData = None  # [32]byte

        # stakeVersion used for voting.
        self.stakeVersion = None  # uint32

        # cachedH is the cached header hash
        self.cachedH = None

    @staticmethod
    def btcDecode(b, pver):
        """
        BtcDecode decodes b using the bitcoin protocol encoding into the
        receiver. This is part of the Message interface implementation.
        See Deserialize for decoding block headers stored to disk, such as
        in a database, as opposed to decoding block headers from the wire.

        Args:
            b (ByteArray): the bytes to decode.
            pver (int): the protocol version.
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
        # TODO: Evaluate the need to interpret the sBits field as signed.
        bh.version = b.pop(int32).unLittle().int()  # int32
        bh.prevBlock = b.pop(HASH_SIZE)  # chainhash.Hash = [32]byte
        bh.merkleRoot = b.pop(HASH_SIZE)  # chainhash.Hash
        bh.stakeRoot = b.pop(HASH_SIZE)  # chainhash.Hash
        bh.voteBits = b.pop(uint16).unLittle().int()  # uint16
        bh.finalState = b.pop(finalStateSize)  # [6]byte
        bh.voters = b.pop(uint16).unLittle().int()  # uint16
        bh.freshStake = b.pop(uint8).unLittle().int()  # uint8
        bh.revocations = b.pop(uint8).unLittle().int()  # uint8
        bh.poolSize = b.pop(uint32).unLittle().int()  # uint32
        bh.bits = b.pop(uint32).unLittle().int()  # uint32
        bh.sBits = b.pop(int64).unLittle().int()  # int64
        bh.height = b.pop(uint32).unLittle().int()  # uint32
        bh.size = b.pop(uint32).unLittle().int()  # uint32
        bh.timestamp = b.pop(uint32).unLittle().int()  # uint32 # time.Time
        bh.nonce = b.pop(uint32).unLittle().int()  # uint32
        bh.extraData = b.pop(extraDataSize)  # [32]byte
        bh.stakeVersion = b.pop(uint32).unLittle().int()  # uint32

        return bh

    def serialize(self):
        """
        Serialize the BlockHeader.

        Returns:
            ByteArray: The serialized BlockHeader.
        """
        return self.btcEncode(0)

    @staticmethod
    def deserialize(b):
        """
        Args:
            b (bytes): the bytes to deserialize.
        """
        return BlockHeader.btcDecode(ByteArray(b), 0)

    # blob and unblob satisfy the Blobber API from  util.database
    @staticmethod
    def blob(blockHeader):
        """Satisfies the encode.Blobber API"""
        return blockHeader.serialize().b

    @staticmethod
    def unblob(b):
        """
        Satisfies the encode.Blobber API.

        Args:
            b (bytes): the bytes to unblob.
        """
        return BlockHeader.deserialize(b)

    def btcEncode(self, pver):
        """
        Args:
            pver (int): the protocol version.
        """
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
        return b

    def hash(self):
        """
        hash computes the block identifier hash for the given block header.
        """
        return crypto.hashH(self.serialize().bytes())

    def cachedHash(self):
        """
        Returns the cached hash. If the hash has not been generated, generate
        the cache first.

        Returns:
            ByteArray: The transaction hash.
        """
        if self.cachedH:
            return self.cachedH
        self.cachedH = self.hash()
        return self.cachedH

    def id(self):
        return reversed(self.hash()).hex()
