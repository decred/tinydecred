"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from tinydecred.dcr.wire import msgblock
from tinydecred.util.encode import ByteArray


class TestBlockHeader(unittest.TestCase):
    def test_decode(self):
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
        b = bh.serialize()
        self.assertEqual(b, encoded)
        reBH = msgblock.BlockHeader.unblob(b)
        self.assertEqual(bh.version, reBH.version)
        self.assertEqual(bh.prevBlock, reBH.prevBlock)
        self.assertEqual(bh.merkleRoot, reBH.merkleRoot)
        self.assertEqual(bh.stakeRoot, reBH.stakeRoot)
        self.assertEqual(bh.voteBits, reBH.voteBits)
        self.assertEqual(bh.finalState, reBH.finalState)
        self.assertEqual(bh.voters, reBH.voters)
        self.assertEqual(bh.freshStake, reBH.freshStake)
        self.assertEqual(bh.revocations, reBH.revocations)
        self.assertEqual(bh.poolSize, reBH.poolSize)
        self.assertEqual(bh.bits, reBH.bits)
        self.assertEqual(bh.sBits, reBH.sBits)
        self.assertEqual(bh.height, reBH.height)
        self.assertEqual(bh.size, reBH.size)
        self.assertEqual(bh.timestamp, reBH.timestamp)
        self.assertEqual(bh.nonce, reBH.nonce)
        self.assertEqual(bh.extraData, reBH.extraData)
        self.assertEqual(bh.stakeVersion, reBH.stakeVersion)
        self.assertEqual(bh.id(), reBH.id())
