"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2020, The Decred developers
See LICENSE for details

Some network math.
"""

import bisect
import math

from decred import DecredError
from decred.util import helpers

from . import constants as C
from .nets import mainnet


NETWORK = mainnet
MODEL_DEVICE = {
    "model": "INNOSILICON D9 Miner",
    "price": 1699,
    "release": "2018-04-18",
    "hashrate": 2.1e12,
    "power": 900,
}


def makeDevice(
    model=None, price=None, hashrate=None, power=None, release=None, source=None
):
    """
    Create a device
    """
    device = {
        "model": model,
        "price": price,
        "hashrate": hashrate,
        "power": power,
        "release": release,
        "source": source,
    }
    device["daily.power.cost"] = C.PRIME_POWER_RATE * device["power"] / 1000 * 24
    device["min.profitability"] = -1 * device["daily.power.cost"] / device["price"]
    device["power.efficiency"] = device["hashrate"] / device["power"]
    device["relative.price"] = device["price"] / device["hashrate"]
    if release and isinstance(release, str):
        device["release"] = helpers.mktime(
            *[int(x) for x in device["release"].split("-")]
        )
    return device


def setNetwork(network):
    global NETWORK
    NETWORK = network


def clamp(val, minVal, maxVal):
    return max(minVal, min(val, maxVal))


def interpolate(pts, x):
    """
    Linearly interpret between points to get an estimate.
    pts should be of the form ((x1,y1), (x2,y2), ..) of increasing x.
    """
    lastPt = pts[0]
    for pt in pts[1:]:
        t, v = pt
        lt, lv = lastPt
        if t >= x:
            return lv + (x - lt) / (t - lt) * (v - lv)
        lastPt = pt


def derivative(pts, x):
    """
    Slope of line between two points. (δy/δx).
    pts should be of the form ((x1,y1), (x2,y2), ..) of increasing x.
    """

    lastPt = pts[0]
    for pt in pts[1:]:
        t, v = pt
        if t >= x:
            lt, lv = lastPt
            return (v - lv) / (t - lt)
        lastPt = pt


def getCirculatingSupply(tBlock):
    """
    An approximation based on standard block time of 5 min and timestamp of
    genesis block.
    """
    if tBlock < NETWORK.GENESIS_STAMP:
        return 0
    premine = 1.68e6
    if tBlock == NETWORK.GENESIS_STAMP:
        return premine
    block2reward = 21.84
    block4096stamp = helpers.mktime(2016, 2, 22)
    if tBlock < block4096stamp:
        return (
            premine
            + (tBlock - NETWORK.GENESIS_STAMP)
            / NETWORK.TargetTimePerBlock
            * block2reward
        )
    block4096reward = 31.20
    regularStamp = (
        NETWORK.GENESIS_STAMP
        + NETWORK.SubsidyReductionInterval * NETWORK.TargetTimePerBlock
    )
    if tBlock < regularStamp:
        return (
            premine
            + (tBlock - NETWORK.GENESIS_STAMP)
            / NETWORK.TargetTimePerBlock
            * block4096reward
        )
    tRemain = tBlock - regularStamp
    blockCount = tRemain / NETWORK.TargetTimePerBlock
    periods = blockCount / float(NETWORK.SubsidyReductionInterval)
    vSum = 1833321  # supply at start of regular reward period
    fullPeriods = int(periods)
    partialPeriod = periods - fullPeriods
    p = 0
    for p in range(fullPeriods):
        reward = blockReward((p + 1) * NETWORK.SubsidyReductionInterval)
        vSum += reward * NETWORK.SubsidyReductionInterval
    p += 1
    reward = blockReward((p + 1) * NETWORK.SubsidyReductionInterval)
    vSum += reward * NETWORK.SubsidyReductionInterval * partialPeriod
    return vSum


def timeToHeight(t):
    """
    Approximate the height based on the time.
    """
    return int((t - NETWORK.GENESIS_STAMP) / NETWORK.TargetTimePerBlock)


def binomial(n, k):
    f = math.factorial
    return f(n) / f(k) / f(n - k)


def concensusProbability(stakeportion, winners=None, participation=1):
    """
    This is the binomial distribution form rather than the hypergeometric.
    The two converge at ticketPoolSize >> winners.
    """
    winners = winners if winners else NETWORK.TicketsPerBlock
    halfN = winners / 2.0
    k = 0
    probability = 0
    while k < halfN:
        probability += (
            binomial(winners, k)
            * stakeportion ** (winners - k)
            * ((1 - stakeportion) * participation) ** k
        )
        k += 1
    if probability == 0:
        print(
            "Quitting with parameters %s" % repr((stakeportion, winners, participation))
        )
    return probability


def hashportion(stakeportion, winners=None, participation=1):
    """
    The portion of the blockchain that would need to be under
    attacker control for an attack to be initiated.
    """
    winners = winners if winners else NETWORK.TicketsPerBlock
    return 1 - concensusProbability(stakeportion, winners)


def dailyPowRewards(height, blockTime=None, powSplit=None):
    """
    Approximation of the total daily payout in DCR.
    """
    powSplit = powSplit if powSplit else NETWORK.POW_SPLIT
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    return C.DAY / blockTime * blockReward(height) * powSplit


def dailyPosRewards(height, blockTime=None, stakeSplit=None):
    """
    Approximation of the total daily POS rewards.
    """
    stakeSplit = stakeSplit if stakeSplit else NETWORK.STAKE_SPLIT
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    return C.DAY / blockTime * blockReward(height) * stakeSplit


def blockReward(height):
    """
    https://docs.decred.org/advanced/inflation/
    I think this is actually wrong for height < 4096
    """
    return 31.19582664 * (100 / 101) ** int(height / 6144)


class ReverseEquations:
    """
    A bunch of static methods for going backwards from profitability to
    common network parameters
    """

    @staticmethod
    def grossEarnings(device, roi, energyRate=None):
        energyRate = energyRate if energyRate else C.PRIME_POWER_RATE
        return roi * device["price"] + 24 * device["power"] * energyRate / 1000

    @staticmethod
    def networkDeviceCount(
        device, xcRate, roi, height=3e5, blockTime=None, powSplit=None
    ):
        powSplit = powSplit if powSplit else NETWORK.POW_SPLIT
        blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
        return (
            dailyPowRewards(height, blockTime, powSplit)
            * xcRate
            / ReverseEquations.grossEarnings(device, roi)
        )

    @staticmethod
    def networkHashrate(device, xcRate, roi, height=3e5, blockTime=None, powSplit=None):
        powSplit = powSplit if powSplit else NETWORK.POW_SPLIT
        blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
        return (
            ReverseEquations.networkDeviceCount(
                device, xcRate, roi, height, blockTime, powSplit
            )
            * device["hashrate"]
        )

    @staticmethod
    def ticketPrice(apy, height, winners=None, stakeSplit=None):
        winners = winners if winners else NETWORK.TicketsPerBlock
        stakeSplit = stakeSplit if stakeSplit else NETWORK.STAKE_SPLIT
        Rpos = stakeSplit * blockReward(height)
        return Rpos / (winners * ((apy + 1) ** (25 / 365.0) - 1))


class Ay:
    """
    The parametrized cost of attack result.
    """

    def __init__(self, retailTerm, rentalTerm, stakeTerm, ticketFraction):
        self.retailTerm = retailTerm
        self.rentalTerm = rentalTerm
        self.stakeTerm = stakeTerm
        self.workTerm = rentalTerm + retailTerm
        self.attackCost = retailTerm + rentalTerm + stakeTerm
        self.ticketFraction = ticketFraction

    def __str__(self):
        return (
            "<AttackCost: ticketFraction %.3f, workTerm %i, stakeTerm %i, attackCost %i>"
            % (self.ticketFraction, self.workTerm, self.stakeTerm, self.attackCost)
        )


def attackCost(
    ticketFraction=None,
    xcRate=None,
    blockHeight=None,
    roi=None,
    ticketPrice=None,
    blockTime=None,
    powSplit=None,
    stakeSplit=None,
    treasurySplit=None,
    rentability=None,
    nethash=None,
    winners=None,
    participation=1.0,
    poolSize=None,
    apy=None,
    attackDuration=C.HOUR,
    device=None,
    rentalRatio=None,
    rentalRate=None,
):
    """
    Calculate the cost of attack, which is the minimum fiat value of equipment, tickets,
    and rental expenditures required to outpace the main chain.

    The cost of attack can be calculated in direct mode or reverse mode, depending on
    the parameters provided.
    Provide a `nethash` and a `ticketPrice` to calculate in direct mode.
    Omit the `nethash` and `ticketPrice`, and instead provide an `roi` and `apy` to
    calculate in reverse mode.
    In reverse mode, (xcRate, roi, blockHeight, blockTime, powSplit) are used to
    calculate a network hashrate, and the (apy, blockHeight, winners, stakeSplit)
    are used to calculate a ticketPrice.

    :param float ticketFraction: required. The fraction of the stakepool under attacker
        control.
    :param float xcRate: required. The fiat exchange rate.
    :param int blockHeight: required. The height of the blockchain at the time of attack.
    :param roi float: The miner return-on-investment (\alpha). Only used in reverse mode.
    :param  float ticketPrice: The price of the ticket. Providing the ticketPrice causes
        direct-mode calculation.
    :param int blockTime: The network's target block time. Unix timestamp. Default
        NETWORK.TargetTimePerBlock
    :param float powSplit: The fraction of the block reward given to the POW miners.
        Only used in reverse mode.
    :param float stakeSplit: The fraction of the block reward given to the stakeholders.
        Only used in reverse mode.
    :param float treasurySplit: The fraction of the block reward given to the Decred
        treasury. Only used in reverse mode.
    :param int rentability: The total hashrate avaialable on the rental market.
        See also rentalRatio.
    :param int nethash: The network hashrate. Providing the ticketPrice causes
        direct-mode calculation.
    :param int winners: The number of tickets selected per block.
        default NETWORK.TicketsPerBlock
    :param float participation: The fraction of stakeholders online and ready
        to validate.
    :param int poolSize: The network target for ticket pool size.
        default NETWORK.TicketExpiry
    :param float apy: The annual percentage yield. Used only in reverse mode.
        apy = (ticketReturnRate + 1)**(365/28)
    :param float attackDuration: The length of the attack, in seconds.
    :param dict device: Device see MODEL_DEVICE and makeDevice for required attributes.
    :param float rentalRatio: An alternative to rentability.
        The fraction of required hashpower that is available for rent.
    :param float rentalRate: The rental rate, in fiat/hash.
    """
    if any([x is None for x in (ticketFraction, xcRate, blockHeight)]):
        raise DecredError(
            "ticketFraction, xcRate, and blockHeight are required args/kwargs"
            " for AttackCost"
        )
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    winners = winners if winners else NETWORK.TicketsPerBlock
    poolSize = poolSize if poolSize else NETWORK.TicketExpiry
    treasurySplit = treasurySplit if treasurySplit else NETWORK.TREASURY_SPLIT
    if treasurySplit is None:
        raise DecredError("AttackCost: treasurySplit cannot be None")

    if stakeSplit:
        if not powSplit:
            powSplit = 1 - treasurySplit - stakeSplit
    else:
        if powSplit:
            stakeSplit = 1 - treasurySplit - powSplit
        else:
            powSplit = NETWORK.POW_SPLIT
            stakeSplit = NETWORK.STAKE_SPLIT

    device = device if device else MODEL_DEVICE
    if nethash is None:
        if roi is None:  # mining ROI could be zero
            raise DecredError("minimizeY: Either a nethash or an roi must be provided")
        nethash = ReverseEquations.networkHashrate(
            device, xcRate, roi, blockHeight, blockTime, powSplit
        )
    if rentability or rentalRatio:
        if not rentalRate:
            raise DecredError(
                "minimizeY: If rentability is non-zero, rentalRate must be provided"
            )
    else:
        rentalRate = 0
    if ticketPrice is None:
        if not apy:
            raise DecredError(
                "minimizeY: Either a ticketPrice or an apy must be provided"
            )
        ticketPrice = ReverseEquations.ticketPrice(
            apy, blockHeight, winners, stakeSplit
        )
    stakeTerm = ticketFraction * poolSize * ticketPrice * xcRate
    hashPortion = hashportion(ticketFraction, winners, participation)
    attackHashrate = nethash * hashPortion
    rent = (
        rentability
        if rentability is not None
        else attackHashrate * rentalRatio
        if rentalRatio is not None
        else 0
    )
    rentalPart = min(rent, attackHashrate)
    retailPart = attackHashrate - rentalPart
    rentalTerm = rentalPart * rentalRate / 86400 * attackDuration
    retailTerm = retailPart * (
        device["relative.price"]
        + device["power"]
        / device["hashrate"]
        * C.PRIME_POWER_RATE
        / 1000
        / 3600
        * attackDuration
    )
    return Ay(retailTerm, rentalTerm, stakeTerm, ticketFraction)


def purePowAttackCost(
    xcRate=None,
    blockHeight=None,
    roi=None,
    blockTime=None,
    treasurySplit=None,
    rentability=None,
    nethash=None,
    attackDuration=C.HOUR,
    device=None,
    rentalRatio=None,
    rentalRate=None,
    **kwargs
):
    if any([x is None for x in (xcRate, blockHeight)]):
        raise DecredError(
            "xcRate and blockHeight are required args/kwargs for PurePowAttackCost"
        )
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    device = device if device else MODEL_DEVICE
    treasurySplit = treasurySplit if treasurySplit else NETWORK.TREASURY_SPLIT
    if nethash is None:
        if roi is None:  # mining ROI could be zero
            raise DecredError("minimizeY: Either a nethash or an roi must be provided")
        nethash = ReverseEquations.networkHashrate(
            device, xcRate, roi, blockHeight, blockTime, 1 - treasurySplit
        )
    if rentability or rentalRatio:
        if not rentalRate:
            raise DecredError(
                "minimizeY: If rentability is non-zero, rentalRate must be provided"
            )
    else:
        rentalRate = 0
    attackHashrate = 0.5 * nethash
    rent = (
        rentability
        if rentability is not None
        else attackHashrate * rentalRatio
        if rentalRatio is not None
        else 0
    )
    rentalPart = min(rent, attackHashrate)
    retailPart = attackHashrate - rentalPart
    rentalTerm = rentalPart * rentalRate / 86400 * attackDuration
    retailTerm = retailPart * (
        device["relative.price"]
        + device["power"]
        / device["hashrate"]
        * C.PRIME_POWER_RATE
        / 1000
        / 3600
        * attackDuration
    )
    return Ay(retailTerm, rentalTerm, 0, 0)


def minimizeAy(*args, grains=100, **kwargs):
    lowest = C.INF
    result = None
    grainSize = 0.999 / grains
    for i in range(1, grains):
        A = attackCost(grainSize * i, *args, **kwargs)
        if A.attackCost < lowest:
            lowest = A.attackCost
            result = A
    return result


class SubsidyCache:
    """
    SubsidyCache provides efficient access to consensus-critical subsidy
    calculations for blocks and votes, including the max potential subsidy for
    given block heights, the proportional proof-of-work subsidy, the proportional
    proof of stake per-vote subsidy, and the proportional treasury subsidy.

    It makes use of caching to avoid repeated calculations.
    """

    def __init__(self, netParams):
        """
        Args:
            netParams (module): The network parameters.
        """
        # netParams stores the subsidy parameters to use during subsidy
        # calculation.
        self.netParams = netParams

        # cache houses the cached subsidies keyed by reduction interval.
        self.cache = {0: netParams.BaseSubsidy}

        # cachedIntervals contains an ordered list of all cached intervals.
        # It is used to efficiently track sparsely cached intervals with
        # O(log N) discovery of a prior cached interval.
        self.cachedIntervals = [0]

        # These fields house values calculated from the parameters in order to
        # avoid repeated calculation.
        #
        # minVotesRequired is the minimum number of votes required for a block to
        # be consider valid by consensus.
        #
        # totalProportions is the sum of the PoW, PoS, and Treasury proportions.
        self.minVotesRequired = (netParams.TicketsPerBlock // 2) + 1
        self.totalProportions = (
            netParams.WorkRewardProportion
            + netParams.StakeRewardProportion
            + netParams.BlockTaxProportion
        )

    def calcBlockSubsidy(self, height):
        """
        calcBlockSubsidy returns the max potential subsidy for a block at the
        provided height.  This value is reduced over time based on the height and
        then split proportionally between PoW, PoS, and the Treasury.
        """
        # Negative block heights are invalid and produce no subsidy.
        # Block 0 is the genesis block and produces no subsidy.
        # Block 1 subsidy is special as it is used for initial token distribution.
        if height <= 0:
            return 0
        elif height == 1:
            return self.netParams.BlockOneSubsidy

        # Calculate the reduction interval associated with the requested height and
        # attempt to look it up in cache.  When it's not in the cache, look up the
        # latest cached interval and subsidy.
        reqInterval = height // self.netParams.SubsidyReductionInterval
        if reqInterval in self.cache:
            return self.cache[reqInterval]

        lastCachedInterval = self.cachedIntervals[len(self.cachedIntervals) - 1]
        lastCachedSubsidy = self.cache[lastCachedInterval]

        # When the requested interval is after the latest cached interval, avoid
        # additional work by either determining if the subsidy is already exhausted
        # at that interval or using the interval as a starting point to calculate
        # and store the subsidy for the requested interval.
        #
        # Otherwise, the requested interval is prior to the final cached interval,
        # so use a binary search to find the latest cached interval prior to the
        # requested one and use it as a starting point to calculate and store the
        # subsidy for the requested interval.
        if reqInterval > lastCachedInterval:
            # Return zero for all intervals after the subsidy reaches zero.  This
            # enforces an upper bound on the number of entries in the cache.
            if lastCachedSubsidy == 0:
                return 0
        else:
            cachedIdx = bisect.bisect_left(self.cachedIntervals, reqInterval)
            lastCachedInterval = self.cachedIntervals[cachedIdx - 1]
            lastCachedSubsidy = self.cache[lastCachedInterval]

        # Finally, calculate the subsidy by applying the appropriate number of
        # reductions per the starting and requested interval.
        reductionMultiplier = self.netParams.MulSubsidy
        reductionDivisor = self.netParams.DivSubsidy
        subsidy = lastCachedSubsidy
        neededIntervals = reqInterval - lastCachedInterval
        for i in range(neededIntervals):
            subsidy *= reductionMultiplier
            subsidy = subsidy // reductionDivisor

            # Stop once no further reduction is possible.  This ensures a bounded
            # computation for large requested intervals and that all future
            # requests for intervals at or after the final reduction interval
            # return 0 without recalculating.
            if subsidy == 0:
                reqInterval = lastCachedInterval + i + 1
                break

        # Update the cache for the requested interval or the interval in which the
        # subsidy became zero when applicable.  The cached intervals are stored in
        # a map for O(1) lookup and also tracked via a sorted array to support the
        # binary searches for efficient sparse interval query support.
        self.cache[reqInterval] = subsidy

        bisect.insort_left(self.cachedIntervals, reqInterval)
        return subsidy

    def calcWorkSubsidy(self, height, voters):
        # The first block has special subsidy rules.
        if height == 1:
            return self.netParams.BlockOneSubsidy

        # The subsidy is zero if there are not enough voters once voting begins.  A
        # block without enough voters will fail to validate anyway.
        stakeValidationHeight = self.netParams.StakeValidationHeight
        if height >= stakeValidationHeight and voters < self.minVotesRequired:
            return 0

        # Calculate the full block subsidy and reduce it according to the PoW
        # proportion.
        subsidy = self.calcBlockSubsidy(height)
        subsidy *= self.netParams.WorkRewardProportion
        subsidy = subsidy // self.totalProportions

        # Ignore any potential subsidy reductions due to the number of votes prior
        # to the point voting begins.
        if height < stakeValidationHeight:
            return subsidy

        # Adjust for the number of voters.
        return (voters * subsidy) // self.netParams.TicketsPerBlock

    def calcStakeVoteSubsidy(self, height):
        """
        CalcStakeVoteSubsidy returns the subsidy for a single stake vote for a block.
        It is calculated as a proportion of the total subsidy and max potential
        number of votes per block.

        Unlike the Proof-of-Work and Treasury subsidies, the subsidy that votes
        receive is not reduced when a block contains less than the maximum number of
        votes.  Consequently, this does not accept the number of votes.  However, it
        is important to note that blocks that do not receive the minimum required
        number of votes for a block to be valid by consensus won't actually produce
        any vote subsidy either since they are invalid.

        This function is safe for concurrent access.
        """
        # Votes have no subsidy prior to the point voting begins.  The minus one
        # accounts for the fact that vote subsidy are, unfortunately, based on the
        # height that is being voted on as opposed to the block in which they are
        # included.
        if height < self.netParams.StakeValidationHeight - 1:
            return 0

        # Calculate the full block subsidy and reduce it according to the stake
        # proportion.  Then divide it by the number of votes per block to arrive
        # at the amount per vote.
        subsidy = self.calcBlockSubsidy(height)
        proportions = self.totalProportions
        subsidy *= self.netParams.StakeRewardProportion
        subsidy = subsidy // (proportions * self.netParams.TicketsPerBlock)

        return subsidy

    def calcTreasurySubsidy(self, height, voters):
        """
        calcTreasurySubsidy returns the subsidy required to go to the treasury for
        a block.  It is calculated as a proportion of the total subsidy and further
        reduced proportionally depending on the number of votes once the height at
        which voting begins has been reached.

        Note that passing a number of voters fewer than the minimum required for a
        block to be valid by consensus along with a height greater than or equal to
        the height at which voting begins will return zero.

        This function is safe for concurrent access.
        """
        # The first two blocks have special subsidy rules.
        if height <= 1:
            return 0

        # The subsidy is zero if there are not enough voters once voting begins.  A
        # block without enough voters will fail to validate anyway.
        stakeValidationHeight = self.netParams.StakeValidationHeight
        if height >= stakeValidationHeight and voters < self.minVotesRequired:
            return 0

        # Calculate the full block subsidy and reduce it according to the treasury
        # proportion.
        subsidy = self.calcBlockSubsidy(height)
        subsidy *= self.netParams.BlockTaxProportion
        subsidy = subsidy // self.totalProportions

        # Ignore any potential subsidy reductions due to the number of votes prior
        # to the point voting begins.
        if height < stakeValidationHeight:
            return subsidy

        # Adjust for the number of voters.
        return (voters * subsidy) // self.netParams.TicketsPerBlock


def blksLeftStakeWindow(net, height):
    """
    Return the number of blocks until the next stake difficulty change.

        Args:
            net (module): The network parameters.
            height (int): Block height to find remaining blocks from.

        Returns:
            int: The number of blocks left in the current window.
    """
    window = net.StakeDiffWindowSize
    # Add one to height to account for the genesis block.
    return window - (height + 1) % window
