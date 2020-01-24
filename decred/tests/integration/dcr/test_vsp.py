"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from decred.dcr import testnet, vsp


class TestVSPLive(unittest.TestCase):
    def setUp(self):
        self.poolURL = "https://teststakepool.decred.org"
        self.apiKey = ""
        # signing address is needed to validate server-reported redeem script.
        self.signingAddress = ""
        if not self.apiKey or not self.signingAddress:
            print(" no stake pool credentials provided. skipping stake pool test")
            raise unittest.SkipTest

    def stakePool(self):
        stakePool = vsp.VotingServiceProvider(self.poolURL, self.apiKey, testnet.Name)
        stakePool.authorize(self.signingAddress)
        return stakePool

    def test_get_purchase_info(self):
        stakePool = self.stakePool()
        stakePool.getPurchaseInfo()

    def test_get_stats(self):
        stakePool = self.stakePool()
        stakePool.getStats()

    def test_voting(self):
        stakePool = self.stakePool()
        pi = stakePool.getPurchaseInfo()
        if pi.voteBits & (1 << 1) != 0:
            nextVote = 1 | (1 << 2)
        else:
            nextVote = 1 | (1 << 1)
        print("changing vote from %d to %d" % (pi.voteBits, nextVote))
        stakePool.setVoteBits(nextVote)
        pi = stakePool.getPurchaseInfo()
        self.assertEqual(pi.voteBits, nextVote)
