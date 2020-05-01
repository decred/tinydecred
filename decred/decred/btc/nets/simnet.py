"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

simnet holds simnet parameters. Any values should mirror exactly
https://github.com/btcsuite/btcd/blob/master/chaincfg/params.go
"""

Name = "simnet"
DefaultPort = "18555"
DNSSeeds = []  # NOTE: There must NOT be any seeds.

# Chain parameters
GenesisHash = "683e86bd5c6d110d91b94b97137ba6bfe02dbbdb8e3dff722a669b5d69d77af6"
PowLimit = 2 ^ 255 - 1
PowLimitBits = 0x207FFFFF
BIP0034Height = 0  # Always active on simnet
BIP0065Height = 0  # Always active on simnet
BIP0066Height = 0  # Always active on simnet
CoinbaseMaturity = 100
SubsidyReductionInterval = 210000
TargetTimespan = 60 * 60 * 24 * 14  # 14 days
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
RuleChangeActivationThreshold = 75  # 75% of MinerConfirmationWindow
MinerConfirmationWindow = 100

# Mempool parameters
RelayNonStdTxs = True

# Human-readable part for Bech32 encoded segwit addresses, as defined in
# BIP 173.
Bech32HRPSegwit = "sb"  # always sb for sim net

# Address encoding magics
PubKeyHashAddrID = 0x3F  # starts with S
ScriptHashAddrID = 0x7B  # starts with s
PrivateKeyID = 0x64  # starts with 4 (uncompressed) or F (compressed)
WitnessPubKeyHashAddrID = 0x19  # starts with Gg
WitnessScriptHashAddrID = 0x28  # starts with ?

# BIP32 hierarchical deterministic extended key magics
HDPrivateKeyID = (0x0420B900).to_bytes(4, byteorder="big")  # starts with sprv
HDPublicKeyID = (0x0420BD3A).to_bytes(4, byteorder="big")  # starts with spub

# BIP44 coin type used in the hierarchical deterministic path for
# address generation.
HDCoinType = 115  # ASCII for s
