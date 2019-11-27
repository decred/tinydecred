"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest
from tinydecred.pydecred.wire import msgblock
from tinydecred.crypto.bytearray import ByteArray

class TestBlockHeader(unittest.TestCase):
    def test_decode(self):
        encoded = "060000000bd25508e99bf6f8399efce65762b55873d69dd05a7871631ac8fa7a36f1d05c977ea75040b905415cbc8f7dd519831a031ef5cd9c6a187a9eab8136c8b44fda000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000ffff7f20204e0000000000001b00000066010000aadd025d00000000255221163779dfe800000000000000000000000000000000000000000000000000000000"
        header = msgblock.BlockHeader.deserialize(ByteArray(encoded))
        print("version: %s" % repr(header.version))
        print("prevBlock: %s" % repr(reversed(header.prevBlock).hex()))
        print("merkleRoot: %s" % repr(reversed(header.merkleRoot).hex()))
        print("stakeRoot: %s" % repr(reversed(header.stakeRoot).hex()))
        print("voteBits: %s" % repr(header.voteBits))
        print("finalState: %s" % repr(reversed(header.finalState).hex()))
        print("voters: %s" % repr(header.voters))
        print("freshStake: %s" % repr(header.freshStake))
        print("revocations: %s" % repr(header.revocations))
        print("poolSize: %s" % repr(header.poolSize))
        print("bits: %s" % repr(header.bits))
        print("sBits: %s" % repr(header.sBits))
        print("height: %s" % repr(header.height))
        print("size: %s" % repr(header.size))
        print("timestamp: %s" % repr(header.timestamp))
        print("nonce: %s" % repr(header.nonce))
        print("extraData: %s" % repr(header.extraData.hex()))
        print("stakeVersion: %s" % repr(header.stakeVersion))
        recoded = header.serialize().hex()
        self.assertEqual(recoded, encoded)
        self.assertEqual(header.id(), "52dc18bd18910e0e785411305b04f1281353ab29135a144c0fca9ea4746c2b66")
