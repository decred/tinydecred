"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from tinydecred.dcr import mainnet
from tinydecred.dcr.calc import SubsidyCache
from tinydecred.util import chains


class TestSubsidyCache(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        chains.registerChain("dcr", None)

    def test_subsidy_cache_calcs(self):
        """
        TestSubsidyCacheCalcs ensures the subsidy cache calculates the various
        subsidy proportions and values as expected.
        """

        class test:
            def __init__(
                self,
                name=None,
                params=None,
                height=None,
                numVotes=None,
                wantFull=None,
                wantWork=None,
                wantVote=None,
                wantTreasury=None,
            ):
                self.name = name
                self.params = params
                self.height = height
                self.numVotes = numVotes
                self.wantFull = wantFull
                self.wantWork = wantWork
                self.wantVote = wantVote
                self.wantTreasury = wantTreasury

        tests = [
            test(
                name="negative height",
                params=mainnet,
                height=-1,
                numVotes=0,
                wantFull=0,
                wantWork=0,
                wantVote=0,
                wantTreasury=0,
            ),
            test(
                name="height 0",
                params=mainnet,
                height=0,
                numVotes=0,
                wantFull=0,
                wantWork=0,
                wantVote=0,
                wantTreasury=0,
            ),
            test(
                name="height 1 (initial payouts)",
                params=mainnet,
                height=1,
                numVotes=0,
                wantFull=168000000000000,
                wantWork=168000000000000,
                wantVote=0,
                wantTreasury=0,
            ),
            test(
                name="height 2 (first non-special block prior voting start)",
                params=mainnet,
                height=2,
                numVotes=0,
                wantFull=3119582664,
                wantWork=1871749598,
                wantVote=0,
                wantTreasury=311958266,
            ),
            test(
                name="height 4094 (two blocks prior to voting start)",
                params=mainnet,
                height=4094,
                numVotes=0,
                wantFull=3119582664,
                wantWork=1871749598,
                wantVote=0,
                wantTreasury=311958266,
            ),
            test(
                name="height 4095 (final block prior to voting start)",
                params=mainnet,
                height=4095,
                numVotes=0,
                wantFull=3119582664,
                wantWork=1871749598,
                wantVote=187174959,
                wantTreasury=311958266,
            ),
            test(
                name="height 4096 (voting start), 5 votes",
                params=mainnet,
                height=4096,
                numVotes=5,
                wantFull=3119582664,
                wantWork=1871749598,
                wantVote=187174959,
                wantTreasury=311958266,
            ),
            test(
                name="height 4096 (voting start), 4 votes",
                params=mainnet,
                height=4096,
                numVotes=4,
                wantFull=3119582664,
                wantWork=1497399678,
                wantVote=187174959,
                wantTreasury=249566612,
            ),
            test(
                name="height 4096 (voting start), 3 votes",
                params=mainnet,
                height=4096,
                numVotes=3,
                wantFull=3119582664,
                wantWork=1123049758,
                wantVote=187174959,
                wantTreasury=187174959,
            ),
            test(
                name="height 4096 (voting start), 2 votes",
                params=mainnet,
                height=4096,
                numVotes=2,
                wantFull=3119582664,
                wantWork=0,
                wantVote=187174959,
                wantTreasury=0,
            ),
            test(
                name="height 6143 (final block prior to 1st reduction), 5 votes",
                params=mainnet,
                height=6143,
                numVotes=5,
                wantFull=3119582664,
                wantWork=1871749598,
                wantVote=187174959,
                wantTreasury=311958266,
            ),
            test(
                name="height 6144 (1st block in 1st reduction), 5 votes",
                params=mainnet,
                height=6144,
                numVotes=5,
                wantFull=3088695706,
                wantWork=1853217423,
                wantVote=185321742,
                wantTreasury=308869570,
            ),
            test(
                name="height 6144 (1st block in 1st reduction), 4 votes",
                params=mainnet,
                height=6144,
                numVotes=4,
                wantFull=3088695706,
                wantWork=1482573938,
                wantVote=185321742,
                wantTreasury=247095656,
            ),
            test(
                name="height 12287 (last block in 1st reduction), 5 votes",
                params=mainnet,
                height=12287,
                numVotes=5,
                wantFull=3088695706,
                wantWork=1853217423,
                wantVote=185321742,
                wantTreasury=308869570,
            ),
            test(
                name="height 12288 (1st block in 2nd reduction), 5 votes",
                params=mainnet,
                height=12288,
                numVotes=5,
                wantFull=3058114560,
                wantWork=1834868736,
                wantVote=183486873,
                wantTreasury=305811456,
            ),
            test(
                name="height 307200 (1st block in 50th reduction), 5 votes",
                params=mainnet,
                height=307200,
                numVotes=5,
                wantFull=1896827356,
                wantWork=1138096413,
                wantVote=113809641,
                wantTreasury=189682735,
            ),
            test(
                name="height 307200 (1st block in 50th reduction), 3 votes",
                params=mainnet,
                height=307200,
                numVotes=3,
                wantFull=1896827356,
                wantWork=682857847,
                wantVote=113809641,
                wantTreasury=113809641,
            ),
            test(
                name="height 10911744 (first zero vote subsidy 1776th reduction), 5 votes",
                params=mainnet,
                height=10911744,
                numVotes=5,
                wantFull=16,
                wantWork=9,
                wantVote=0,
                wantTreasury=1,
            ),
            test(
                name="height 10954752 (first zero treasury subsidy 1783rd reduction), 5 votes",
                params=mainnet,
                height=10954752,
                numVotes=5,
                wantFull=9,
                wantWork=5,
                wantVote=0,
                wantTreasury=0,
            ),
            test(
                name="height 11003904 (first zero work subsidy 1791st reduction), 5 votes",
                params=mainnet,
                height=11003904,
                numVotes=5,
                wantFull=1,
                wantWork=0,
                wantVote=0,
                wantTreasury=0,
            ),
            test(
                name="height 11010048 (first zero full subsidy 1792nd reduction), 5 votes",
                params=mainnet,
                height=11010048,
                numVotes=5,
                wantFull=0,
                wantWork=0,
                wantVote=0,
                wantTreasury=0,
            ),
        ]

        for t in tests:
            # Ensure the full subsidy is the expected value.
            cache = SubsidyCache(t.params)
            fullSubsidyResult = cache.calcBlockSubsidy(t.height)
            self.assertEqual(fullSubsidyResult, t.wantFull, t.name)

            # Ensure the PoW subsidy is the expected value.
            workResult = cache.calcWorkSubsidy(t.height, t.numVotes)
            self.assertEqual(workResult, t.wantWork, t.name)

            # Ensure the vote subsidy is the expected value.
            voteResult = cache.calcStakeVoteSubsidy(t.height)
            self.assertEqual(voteResult, t.wantVote, t.name)

            # Ensure the treasury subsidy is the expected value.
            treasuryResult = cache.calcTreasurySubsidy(t.height, t.numVotes)
            self.assertEqual(treasuryResult, t.wantTreasury, t.name)

    def test_total_subsidy(self):
        """
        TestTotalSubsidy ensures the total subsidy produced matches the expected
        value.
        """
        # Locals for convenience.
        reductionInterval = mainnet.SubsidyReductionInterval
        stakeValidationHeight = mainnet.StakeValidationHeight
        votesPerBlock = mainnet.TicketsPerBlock

        # subsidySum returns the sum of the individual subsidy types for the given
        # height.  Note that this value is not exactly the same as the full subsidy
        # originally used to calculate the individual proportions due to the use
        # of integer math.
        cache = SubsidyCache(mainnet)

        def subsidySum(height):
            work = cache.calcWorkSubsidy(height, votesPerBlock)
            vote = cache.calcStakeVoteSubsidy(height) * votesPerBlock
            treasury = cache.calcTreasurySubsidy(height, votesPerBlock)
            return work + vote + treasury

        # Calculate the total possible subsidy.
        totalSubsidy = mainnet.BlockOneSubsidy
        reductionNum = -1
        while True:
            reductionNum += 1
            # The first interval contains a few special cases:
            # 1) Block 0 does not produce any subsidy
            # 2) Block 1 consists of a special initial coin distribution
            # 3) Votes do not produce subsidy until voting begins
            if reductionNum == 0:
                # Account for the block up to the point voting begins ignoring the
                # first two special blocks.
                subsidyCalcHeight = 2
                nonVotingBlocks = stakeValidationHeight - subsidyCalcHeight
                totalSubsidy += subsidySum(subsidyCalcHeight) * nonVotingBlocks

                # Account for the blocks remaining in the interval once voting
                # begins.
                subsidyCalcHeight = stakeValidationHeight
                votingBlocks = reductionInterval - subsidyCalcHeight
                totalSubsidy += subsidySum(subsidyCalcHeight) * votingBlocks
                continue

            # Account for the all other reduction intervals until all subsidy has
            # been produced.
            subsidyCalcHeight = reductionNum * reductionInterval
            subSum = subsidySum(subsidyCalcHeight)
            if subSum == 0:
                break
            totalSubsidy += subSum * reductionInterval

        # Ensure the total calculated subsidy is the expected value.
        self.assertEqual(totalSubsidy, 2099999999800912)

    # TestCalcBlockSubsidySparseCaching ensures the cache calculations work
    # properly when accessed sparsely and out of order.
    def test_calc_block_subsidy_sparse_caching(self):
        # Mock params used in tests.
        # perCacheTest describes a test to run against the same cache.
        class perCacheTest:
            def __init__(self, name, height, want):
                self.name = name
                self.height = height
                self.want = want

        class test:
            def __init__(self, name, params, perCacheTests):
                self.name = name
                self.params = params
                self.perCacheTests = perCacheTests

        tests = [
            test(
                name="negative/zero/one (special cases, no cache)",
                params=mainnet,
                perCacheTests=[
                    perCacheTest(
                        name="would be negative interval", height=-6144, want=0,
                    ),
                    perCacheTest(name="negative one", height=-1, want=0,),
                    perCacheTest(name="height 0", height=0, want=0,),
                    perCacheTest(name="height 1", height=1, want=168000000000000,),
                ],
            ),
            test(
                name="clean cache, negative height",
                params=mainnet,
                perCacheTests=[
                    perCacheTest(
                        name="would be negative interval", height=-6144, want=0,
                    ),
                    perCacheTest(name="height 0", height=0, want=0,),
                ],
            ),
            test(
                name="clean cache, max int64 height twice",
                params=mainnet,
                perCacheTests=[
                    perCacheTest(name="max int64", height=9223372036854775807, want=0,),
                    perCacheTest(
                        name="second max int64", height=9223372036854775807, want=0,
                    ),
                ],
            ),
            test(
                name="sparse out order interval requests with cache hits",
                params=mainnet,
                perCacheTests=[
                    perCacheTest(name="height 0", height=0, want=0,),
                    perCacheTest(name="height 1", height=1, want=168000000000000,),
                    perCacheTest(
                        name="height 2 (cause interval 0 cache addition)",
                        height=2,
                        want=3119582664,
                    ),
                    perCacheTest(
                        name="height 2 (interval 0 cache hit)",
                        height=2,
                        want=3119582664,
                    ),
                    perCacheTest(
                        name="height 3 (interval 0 cache hit)",
                        height=2,
                        want=3119582664,
                    ),
                    perCacheTest(
                        name="height 6145 (interval 1 cache addition)",
                        height=6145,
                        want=3088695706,
                    ),
                    perCacheTest(
                        name="height 6145 (interval 1 cache hit)",
                        height=6145,
                        want=3088695706,
                    ),
                    perCacheTest(
                        name="interval 20 cache addition most recent cache interval 1",
                        height=6144 * 20,
                        want=2556636713,
                    ),
                    perCacheTest(
                        name="interval 20 cache hit", height=6144 * 20, want=2556636713,
                    ),
                    perCacheTest(
                        name="interval 10 cache addition most recent cache interval 20",
                        height=6144 * 10,
                        want=2824117486,
                    ),
                    perCacheTest(
                        name="interval 10 cache hit", height=6144 * 10, want=2824117486,
                    ),
                    perCacheTest(
                        name="interval 15 cache addition between cached 10 and 20",
                        height=6144 * 15,
                        want=2687050883,
                    ),
                    perCacheTest(
                        name="interval 15 cache hit", height=6144 * 15, want=2687050883,
                    ),
                    perCacheTest(
                        name="interval 1792 (first with 0 subsidy) cache addition",
                        height=6144 * 1792,
                        want=0,
                    ),
                    perCacheTest(
                        name="interval 1792 cache hit", height=6144 * 1792, want=0,
                    ),
                    perCacheTest(
                        name="interval 1795 (skipping final 0 subsidy)",
                        height=6144 * 1795,
                        want=0,
                    ),
                ],
            ),
            test(
                name="clean cache, reverse interval requests",
                params=mainnet,
                perCacheTests=[
                    perCacheTest(
                        name="interval 5 cache addition",
                        height=6144 * 5,
                        want=2968175862,
                    ),
                    perCacheTest(
                        name="interval 3 cache addition",
                        height=6144 * 3,
                        want=3027836198,
                    ),
                    perCacheTest(
                        name="interval 3 cache hit", height=6144 * 3, want=3027836198,
                    ),
                ],
            ),
            test(
                name="clean cache, forward non-zero start interval requests",
                params=mainnet,
                perCacheTests=[
                    perCacheTest(
                        name="interval 2 cache addition",
                        height=6144 * 2,
                        want=3058114560,
                    ),
                    perCacheTest(
                        name="interval 12 cache addition",
                        height=6144 * 12,
                        want=2768471213,
                    ),
                    perCacheTest(
                        name="interval 12 cache hit", height=6144 * 12, want=2768471213,
                    ),
                ],
            ),
        ]

        for t in tests:
            cache = SubsidyCache(t.params)
            for pcTest in t.perCacheTests:
                result = cache.calcBlockSubsidy(pcTest.height)
                self.assertEqual(result, pcTest.want, t.name)
