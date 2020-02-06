"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

simnet holds simnet parameters. Any values should mirror exactly
https://github.com/decred/dcrd/blob/master/chaincfg/simnetparams.go
"""

# SimNetParams defines the network parameters for the simulation test network.
# This network is similar to the normal test network except it is intended for
# private use within a group of individuals doing simulation testing and full
# integration tests between different applications such as wallets, voting
# service providers, mining pools, block explorers, and other services that
# build on Decred.
#
# The functionality is intended to differ in that the only nodes which are
# specifically specified are used to create the network rather than following
# normal discovery rules.  This is important as otherwise it would just turn
# into another public testnet.
Name = "simnet"
DefaultPort = "18555"
DNSSeeds = None  # NOTE: There must NOT be any seeds.

# Chain parameters
GenesisHash = "5bec7567af40504e0994db3b573c186fffcc4edefe096ff2e58d00523bd7e8a6"
PowLimit = 2 ** 255 - 1
PowLimitBits = 0x207FFFFF
ReduceMinDifficulty = False
MinDiffReductionTime = 0  # Does not apply since ReduceMinDifficulty fals
GenerateSupported = False
MaximumBlockSizes = [1310720]
MaxTxSize = 1000000
TargetTimePerBlock = 1  # one secon
WorkDiffAlpha = 1
WorkDiffWindowSize = 8
WorkDiffWindows = 4
TargetTimespan = 8  # TimePerBlock * WindowSize
RetargetAdjustmentFactor = 4

# Subsidy parameters.
BaseSubsidy = 50000000000
MulSubsidy = 100
DivSubsidy = 101
SubsidyReductionInterval = 128
WorkRewardProportion = 6
StakeRewardProportion = 3
BlockTaxProportion = 1

# Checkpoints ordered from oldest to newest.
Checkpoints = (None,)

# Consensus rule change deployments.
#
# The miner confirmation window is defined as:
#   target proof of work timespan / target proof of work spacing
# 10% of RuleChangeActivationInterval * TicketsPerBlock
RuleChangeActivationQuorum = 160
RuleChangeActivationMultiplier = 3  # 75%
RuleChangeActivationDivisor = 4
RuleChangeActivationInterval = 320  # 320 seconds

# Enforce current block version once majority of the network has upgraded.
# 51% (51 / 100)
# Reject previous block versions once a majority of the network has upgraded.
# 75% (75 / 100)
BlockEnforceNumRequired = 51
BlockRejectNumRequired = 75
BlockUpgradeNumToCheck = 100

# AcceptNonStdTxs is a mempool param to either accept and relay
# non standard txs to the network or reject them
AcceptNonStdTxs = True

# Address encoding magics
NetworkAddressPrefix = ("S",)
PubKeyAddrID = (0x276F).to_bytes(2, byteorder="big")  # starts with Sk
PubKeyHashAddrID = (0x0E91).to_bytes(2, byteorder="big")  # starts with Ss
PKHEdwardsAddrID = (0x0E71).to_bytes(2, byteorder="big")  # starts with Se
PKHSchnorrAddrID = (0x0E53).to_bytes(2, byteorder="big")  # starts with SS
ScriptHashAddrID = (0x0E6C).to_bytes(2, byteorder="big")  # starts with Sc
PrivateKeyID = (0x2307).to_bytes(2, byteorder="big")  # starts with Ps

# BIP32 hierarchical deterministic extended key magics
HDPrivateKeyID = (0x0420B903).to_bytes(4, byteorder="big")  # starts with sprv
HDPublicKeyID = (0x0420BD3D).to_bytes(4, byteorder="big")  # starts with spub

# BIP44 coin type used in the hierarchical deterministic path for
# address generation.
SLIP0044CoinType = 1  # SLIP0044, Testnet (all coins)
LegacyCoinType = 115  # ASCII for s, for backwards compatibility

# Decred PoS parameters
MinimumStakeDiff = 20000
TicketPoolSize = 64
TicketsPerBlock = 5
TicketMaturity = 16
TicketExpiry = 384  # 6*TicketPoolSize
CoinbaseMaturity = 16
SStxChangeMaturity = 1
TicketPoolSizeWeight = 4
StakeDiffAlpha = 1
StakeDiffWindowSize = 8
StakeDiffWindows = 8
StakeVersionInterval = 8 * 2 * 7
MaxFreshStakePerBlock = 20  # 4*TicketsPerBlock
StakeEnabledHeight = 16 + 16  # CoinbaseMaturity + TicketMaturity
StakeValidationHeight = 16 + (64 * 2)  # CoinbaseMaturity + TicketPoolSize*2
StakeBaseSigScript = (0xDEADBEEF).to_bytes(4, byteorder="big")
StakeMajorityMultiplier = 3
StakeMajorityDivisor = 4

# Decred organization related parameters
#
# Treasury address is a 3-of-3 P2SH going to a wallet with seed:
# aardvark adroitness aardvark adroitness
# aardvark adroitness aardvark adroitness
# aardvark adroitness aardvark adroitness
# aardvark adroitness aardvark adroitness
# aardvark adroitness aardvark adroitness
# aardvark adroitness aardvark adroitness
# aardvark adroitness aardvark adroitness
# aardvark adroitness aardvark adroitness
# briefcase
# (seed 0x0000000000000000000000000000000000000000000000000000000000000000)
#
# This same wallet owns the three ledger outputs for simnet.
#
# P2SH details for simnet treasury:
#
# redeemScript: 532103e8c60c7336744c8dcc7b85c27789950fc52aa4e48f895ebbfb
# ac383ab893fc4c2103ff9afc246e0921e37d12e17d8296ca06a8f92a07fbe7857ed1d4
# f0f5d94e988f21033ed09c7fa8b83ed53e6f2c57c5fa99ed2230c0d38edf53c0340d0f
# c2e79c725a53ae
#   (3-of-3 multisig)
# Pubkeys used:
#   SkQmxbeuEFDByPoTj41TtXat8tWySVuYUQpd4fuNNyUx51tF1csSs
#   SkQn8ervNvAUEX5Ua3Lwjc6BAuTXRznDoDzsyxgjYqX58znY7w9e4
#   SkQkfkHZeBbMW8129tZ3KspEh1XBFC1btbkgzs6cjSyPbrgxzsKqk
#
# Organization address is ScuQxvveKGfpG1ypt6u27F99Anf7EW3cqhq
OrganizationPkScript = (0xA914CBB08D6CA783B533B2C7D24A51FBCA92D937BF9987).to_bytes(
    23, byteorder="big"
)
OrganizationPkScriptVersion = 0
# BlockOneLedger = BlockOneLedgerSimNet,
BlockOneSubsidy = int(300000 * 1e8)
