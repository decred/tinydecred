"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

from decred.dcr.wire import msgblock
from decred.util.encode import ByteArray


class TestBlockHeader:
    def make_block_header(self):
        bh = msgblock.BlockHeader()
        bh.version = 6
        bh.prevBlock = reversed(
            ByteArray(
                "5cd0f1367afac81a6371785ad09dd67358b56257e6fc9e39f8f69be90855d20b"
            )
        )
        bh.merkleRoot = reversed(
            ByteArray(
                "da4fb4c83681ab9e7a186a9ccdf51e031a8319d57d8fbc5c4105b94050a77e97"
            )
        )
        bh.stakeRoot = reversed(
            ByteArray(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
        )
        bh.voteBits = 1
        bh.finalState = ByteArray("000000000000")
        bh.voters = 0
        bh.freshStake = 0
        bh.revocations = 0
        bh.poolSize = 0
        bh.bits = 545259519
        bh.sBits = 20000
        bh.height = 27
        bh.size = 358
        bh.timestamp = 1560468906
        bh.nonce = 0
        bh.extraData = ByteArray(
            "255221163779dfe8000000000000000000000000000000000000000000000000"
        )
        bh.stakeVersion = 0
        encoded = ByteArray(
            "060000000bd25508e99bf6f8399efce65762b55873d69dd05a7871631ac8fa7a36f1d05c"
            "977ea75040b905415cbc8f7dd519831a031ef5cd9c6a187a9eab8136c8b44fda00000000"
            "000000000000000000000000000000000000000000000000000000000100000000000000"
            "0000000000000000ffff7f20204e0000000000001b00000066010000aadd025d00000000"
            "255221163779dfe800000000000000000000000000000000000000000000000000000000"
        )
        return bh, encoded

    def test_decode(self):
        bh, encoded = self.make_block_header()
        b = bh.serialize()
        assert b == encoded
        reBH = msgblock.BlockHeader.unblob(ByteArray.hex(b))
        assert bh.version == reBH.version
        assert bh.prevBlock == reBH.prevBlock
        assert bh.merkleRoot == reBH.merkleRoot
        assert bh.stakeRoot == reBH.stakeRoot
        assert bh.voteBits == reBH.voteBits
        assert bh.finalState == reBH.finalState
        assert bh.voters == reBH.voters
        assert bh.freshStake == reBH.freshStake
        assert bh.revocations == reBH.revocations
        assert bh.poolSize == reBH.poolSize
        assert bh.bits == reBH.bits
        assert bh.sBits == reBH.sBits
        assert bh.height == reBH.height
        assert bh.size == reBH.size
        assert bh.timestamp == reBH.timestamp
        assert bh.nonce == reBH.nonce
        assert bh.extraData == reBH.extraData
        assert bh.stakeVersion == reBH.stakeVersion
        assert bh.id() == reBH.id()

    def test_cached_hash(self):
        bh, _ = self.make_block_header()
        assert bh.cachedH is None
        hash_ = bh.cachedHash()
        assert hash_ == bh.cachedHash()
