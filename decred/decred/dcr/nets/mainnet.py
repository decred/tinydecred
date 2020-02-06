"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

mainnet holds mainnet parameters. Any values should mirror exactly
https://github.com/decred/dcrd/blob/master/chaincfg/mainnetparams.go
"""

from decred.dcr import constants as C


Name = "mainnet"
DefaultPort = "9108"
DNSSeeds = [
    ("mainnet-seed.decred.mindcry.org", True),
    ("mainnet-seed.decred.netpurgatory.com", True),
    ("mainnet-seed.decred.org", True),
]
GenesisHash = "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980"
PowLimit = 2 ^ 224 - 1

# POW parameters
PowLimitBits = 0x1D00FFFF
ReduceMinDifficulty = False
MinDiffReductionTime = 0  # Does not apply since ReduceMinDifficulty false
GenerateSupported = False
MaximumBlockSizes = [393216]
MaxTxSize = 393216
TargetTimePerBlock = C.MINUTE * 5
WorkDiffAlpha = 1
WorkDiffWindowSize = 144
WorkDiffWindows = 20
TargetTimespan = C.MINUTE * 5 * 144  # TimePerBlock * WindowSize
RetargetAdjustmentFactor = 4

# Subsidy parameters.
BaseSubsidy = 3119582664  # 21m
MulSubsidy = 100
DivSubsidy = 101
SubsidyReductionInterval = 6144
WorkRewardProportion = 6
StakeRewardProportion = 3
BlockTaxProportion = 1

# Checkpoints ordered from oldest to newest.
Checkpoints = [
    (440, "0000000000002203eb2c95ee96906730bb56b2985e174518f90eb4db29232d93"),
    (24480, "0000000000000c9d4239c4ef7ef3fb5aaeed940244bc69c57c8c5e1f071b28a6"),
    (48590, "0000000000000d5e0de21a96d3c965f5f2db2c82612acd7389c140c9afe92ba7"),
    (54770, "00000000000009293d067b1126b7de07fc9b2b94ee50dfe0d48c239a7adb072c"),
    (60720, "0000000000000a64475d68ffb9ad89a3d147c0f5138db26b40da9d19d0004117"),
    (65270, "0000000000000021f107601962789b201f0a0cbb98ac5f8c12b93d94e795b441"),
    (75380, "0000000000000e7d13cfc85806aa720fe3670980f5b7d33253e4f41985558372"),
    (85410, "00000000000013ec928074bea6eac9754aa614c7acb20edf300f18b0cd122692"),
    (99880, "0000000000000cb2a9a9ded647b9f78aae51ace32dd8913701d420ead272913c"),
    (123080, "000000000000009ea6e02d0f0424f445ed50686f9ae4aecdf3b268e981114477"),
    (135960, "00000000000001d2f9bbca9177972c0ba45acb40836b72945a75d73b99079498"),
    (139740, "00000000000001397179ae1aff156fb1aea228938d06b83e43b78b1c44527b5b"),
    (155900, "000000000000008557e37fb05177fc5a54e693de20689753639135f85a2dcb2e"),
    (164300, "000000000000009ed067ff51cd5e15f3c786222a5183b20a991a80ce535907a9"),
    (181020, "00000000000000b77d832cb2cbed02908d69323862a53e56345400ad81a6fb8f"),
    (189950, "000000000000007341d8ae2ea7e41f25cee00e1a70a4a3dc1cb055d14ecb2e11"),
    (214672, "0000000000000021d5cbeead55cb7fd659f07e8127358929ffc34cd362209758"),
    (259810, "0000000000000000ee0fbf469a9f32477ffbb46ebd7a280a53c842ab4243f97c"),
    (295940, "0000000000000000148852c8a919addf4043f9f267b13c08df051d359f1622ca"),
]

# The miner confirmation window is defined as:
#   target proof of work timespan / target proof of work spacing
RuleChangeActivationQuorum = (
    4032  # 10 % of RuleChangeActivationInterval * TicketsPerBlock
)
RuleChangeActivationMultiplier = 3  # 75%
RuleChangeActivationDivisor = 4
RuleChangeActivationInterval = 2016 * 4  # 4 weeks


# Enforce current block version once majority of the network has
# upgraded.
# 75% (750 / 1000)
# Reject previous block versions once a majority of the network has
# upgraded.
# 95% (950 / 1000)
BlockEnforceNumRequired = 750
BlockRejectNumRequired = 950
BlockUpgradeNumToCheck = 1000

# AcceptNonStdTxs is a mempool param to either accept and relay
# non standard txs to the network or reject them
AcceptNonStdTxs = False

# Address encoding magics
NetworkAddressPrefix = "D"
PubKeyAddrID = (0x1386).to_bytes(2, byteorder="big")  # starts with Dk
PubKeyHashAddrID = (0x073F).to_bytes(2, byteorder="big")  # starts with Ds
PKHEdwardsAddrID = (0x071F).to_bytes(2, byteorder="big")  # starts with De
PKHSchnorrAddrID = (0x0701).to_bytes(2, byteorder="big")  # starts with DS
ScriptHashAddrID = (0x071A).to_bytes(2, byteorder="big")  # starts with Dc
PrivateKeyID = (0x22DE).to_bytes(2, byteorder="big")  # starts with Pm

# BIP32 hierarchical deterministic extended key magics
HDPrivateKeyID = (0x02FDA4E8).to_bytes(4, byteorder="big")  # starts with dprv
HDPublicKeyID = (0x02FDA926).to_bytes(4, byteorder="big")  # starts with dpub

# BIP44 coin type used in the hierarchical deterministic path for
# address generation.
SLIP0044CoinType = 42  # SLIP0044, Decred
LegacyCoinType = 20  # for backwards compatibility

# Decred PoS parameters
MinimumStakeDiff = 2 * 1e8  # 2 Coin
TicketPoolSize = 8192
TicketsPerBlock = 5
TicketMaturity = 256
TicketExpiry = 40960  # 5*TicketPoolSize
CoinbaseMaturity = 256
SStxChangeMaturity = 1
TicketPoolSizeWeight = 4
StakeDiffAlpha = 1  # Minimal
StakeDiffWindowSize = 144
StakeDiffWindows = 20
StakeVersionInterval = 144 * 2 * 7  # ~1 week
MaxFreshStakePerBlock = 20  # 4*TicketsPerBlock
StakeEnabledHeight = 256 + 256  # CoinbaseMaturity + TicketMaturity
StakeValidationHeight = 4096  # ~14 days
StakeBaseSigScript = (0x0000).to_bytes(2, byteorder="big")
StakeMajorityMultiplier = 3
StakeMajorityDivisor = 4

OrganizationPkScript = (0xA914F5916158E3E2C4551C1796708DB8367207ED13BB87).to_bytes(
    23, byteorder="big"
)
OrganizationPkScriptVersion = 0

# Convenience constants
GENESIS_STAMP = 1454954400
STAKE_SPLIT = 0.3
POW_SPLIT = 0.6
TREASURY_SPLIT = 0.1

BlockOneSubsidy = int(1680000 * 1e8)
