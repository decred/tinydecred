"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

testnet holds testnet3 parameters. Any values should mirror exactly
https://github.com/decred/dcrd/blob/master/chaincfg/testnetparams.go
"""

Name = "testnet3"
DefaultPort = "19108"
DNSSeeds = [
    ("testnet-seed.decred.mindcry.org", True),
    ("testnet-seed.decred.netpurgatory.com", True),
    ("testnet-seed.decred.org", True),
]

GenesisHash = "a649dce53918caf422e9c711c858837e08d626ecfcd198969b24f7b634a49bac"
PowLimit = 2 ^ 232 - 1
PowLimitBits = 0x1E00FFFF
ReduceMinDifficulty = True
MinDiffReductionTime = 60 * 10  # ~99.3% chance to be mined before reduction
GenerateSupported = True
MaximumBlockSizes = [1310720]
MaxTxSize = 1000000
TargetTimePerBlock = 60 * 2
WorkDiffAlpha = 1
WorkDiffWindowSize = 144
WorkDiffWindows = 20
TargetTimespan = 60 * 2 * 144  # TimePerBlock * WindowSize
RetargetAdjustmentFactor = 4

# Subsidy parameters.
BaseSubsidy = 2500000000  # 25 Coin
MulSubsidy = 100
DivSubsidy = 101
SubsidyReductionInterval = 2048
WorkRewardProportion = 6
StakeRewardProportion = 3
BlockTaxProportion = 1

# Consensus rule change deployments.
#
# The miner confirmation window is defined as:
#   target proof of work timespan / target proof of work spacing
RuleChangeActivationQuorum = (
    2520  # 10 % of RuleChangeActivationInterval * TicketsPerBlock
)
RuleChangeActivationMultiplier = 3  # 75%
RuleChangeActivationDivisor = 4
RuleChangeActivationInterval = 5040  # 1 week

# Enforce current block version once majority of the network has
# upgraded.
# 51% (51 / 100)
# Reject previous block versions once a majority of the network has
# upgraded.
# 75% (75 / 100)
BlockEnforceNumRequired = 51
BlockRejectNumRequired = 75
BlockUpgradeNumToCheck = 100

# AcceptNonStdTxs is a mempool param to either accept and relay
# non standard txs to the network or reject them
AcceptNonStdTxs = True

# Address encoding magics
NetworkAddressPrefix = "T"
PubKeyAddrID = (0x28F7).to_bytes(2, byteorder="big")  # starts with Tk
PubKeyHashAddrID = (0x0F21).to_bytes(2, byteorder="big")  # starts with Ts
PKHEdwardsAddrID = (0x0F01).to_bytes(2, byteorder="big")  # starts with Te
PKHSchnorrAddrID = (0x0EE3).to_bytes(2, byteorder="big")  # starts with TS
ScriptHashAddrID = (0x0EFC).to_bytes(2, byteorder="big")  # starts with Tc
PrivateKeyID = (0x230E).to_bytes(2, byteorder="big")  # starts with Pt

# BIP32 hierarchical deterministic extended key magics
HDPrivateKeyID = (0x04358397).to_bytes(4, byteorder="big")  # starts with tprv
HDPublicKeyID = (0x043587D1).to_bytes(4, byteorder="big")  # starts with tpub

# BIP44 coin type used in the hierarchical deterministic path for
# address generation.
SLIP0044CoinType = 1  # SLIP0044, Testnet (all coins)
LegacyCoinType = 11  # for backwards compatibility

# Decred PoS parameters
MinimumStakeDiff = 20000000  # 0.2 Coin
TicketPoolSize = 1024
TicketsPerBlock = 5
TicketMaturity = 16
TicketExpiry = 6144  # 6*TicketPoolSize
CoinbaseMaturity = 16
SStxChangeMaturity = 1
TicketPoolSizeWeight = 4
StakeDiffAlpha = 1
StakeDiffWindowSize = 144
StakeDiffWindows = 20
StakeVersionInterval = 144 * 2 * 7  # ~1 week
MaxFreshStakePerBlock = 20  # 4*TicketsPerBlock
StakeEnabledHeight = 16 + 16  # CoinbaseMaturity + TicketMaturity
StakeValidationHeight = 768  # Arbitrary
StakeBaseSigScript = (0x0000).to_bytes(2, byteorder="big")
StakeMajorityMultiplier = 3
StakeMajorityDivisor = 4

# Decred organization related parameters.
# Organization address is TcrypGAcGCRVXrES7hWqVZb5oLJKCZEtoL1.
OrganizationPkScript = (0xA914D585CD7426D25B4EA5FAF1E6987AACFEDA3DB94287).to_bytes(
    23, byteorder="big"
)
OrganizationPkScriptVersion = 0

GENESIS_STAMP = 1533513600
STAKE_SPLIT = 0.3
POW_SPLIT = 0.6
TREASURY_SPLIT = 0.1

BlockOneSubsidy = int(100000 * 1e8)
