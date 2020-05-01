"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

regtest holds regtest parameters. Any values should mirror exactly
https://github.com/btcsuite/btcd/blob/master/chaincfg/params.go
"""

Name = "regtest"
DefaultPort = "18444"
DNSSeeds = []

# Chain parameters
GenesisHash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
PowLimit = 2 ^ 255 - 1
PowLimitBits = 0x207FFFFF
CoinbaseMaturity = 100
BIP0034Height = 100000000  #  Not active - Permit ver 1 blocks
BIP0065Height = 1351  #  Used by regression tests
BIP0066Height = 1251  #  Used by regression tests
SubsidyReductionInterval = 150  #  TargetTimespan: 14 days
TargetTimePerBlock = 60 * 10  # 10 minutes
RetargetAdjustmentFactor = 4  # 25% less, 400% more
ReduceMinDifficulty = True
MinDiffReductionTime = 60 * 20  # TargetTimePerBlock * 2
GenerateSupported = True

# Checkpoints ordered from oldest to newest.
Checkpoints = []

# Consensus rule change deployments.
#
# The miner confirmation window is defined as:
#   target proof of work timespan / target proof of work spacing
RuleChangeActivationThreshold = 108  # 75%  of MinerConfirmationWindow
MinerConfirmationWindow = 144

# Mempool parameters
RelayNonStdTxs = True

# Human-readable part for Bech32 encoded segwit addresses, as defined in
# BIP 173.
Bech32HRPSegwit = "bcrt"  # always bcrt for reg test net

# Address encoding magics
PubKeyHashAddrID = 0x6F  # starts with m or n
ScriptHashAddrID = 0xC4  # starts with 2
PrivateKeyID = 0xEF  # starts with 9 (uncompressed) or c (compressed)

# BIP32 hierarchical deterministic extended key magics
HDPrivateKeyID = (0x04358394).to_bytes(4, byteorder="big")  # starts with tprv
HDPublicKeyID = (0x043587CF).to_bytes(4, byteorder="big")  # starts with tpub

# BIP44 coin type used in the hierarchical deterministic path for
# address generation.
HDCoinType = 1
