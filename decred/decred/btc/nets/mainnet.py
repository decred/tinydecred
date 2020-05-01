"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

mainnet holds mainnet parameters. Any values should mirror exactly
https://github.com/btcsuite/btcd/blob/master/chaincfg/params.go
"""

Name = "mainnet"
DefaultPort = "8333"
DNSSeeds = [
    ("seed.bitcoin.sipa.be", True),
    ("dnsseed.bluematt.me", True),
    ("dnsseed.bitcoin.dashjr.org", False),
    ("seed.bitcoinstats.com", True),
    ("seed.bitnodes.io", False),
    ("seed.bitcoin.jonasschnelli.ch", True),
]

# Chain parameters
GenesisHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
PowLimit = 2 ^ 224 - 1
PowLimitBits = 0x1D00FFFF
BIP0034Height = (
    227931  # 000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8
)
BIP0065Height = (
    388381  # 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
)
BIP0066Height = (
    363725  # 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
)
CoinbaseMaturity = 100
SubsidyReductionInterval = 210000
TargetTimespan = 60 * 60 * 24 * 14  # 14 days
TargetTimePerBlock = 60 * 10  # 10 minutes
RetargetAdjustmentFactor = 4  # 25% less, 400% more
ReduceMinDifficulty = False
MinDiffReductionTime = 0
GenerateSupported = False

# Checkpoints ordered from oldest to newest.
Checkpoints = [
    (11111, "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
    (33333, "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
    (74000, "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
    (105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
    (134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
    (168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
    (193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
    (210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
    (216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
    (225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
    (250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
    (267300, "000000000000000a83fbd660e918f218bf37edd92b748ad940483c7c116179ac"),
    (279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
    (300255, "0000000000000000162804527c6e9b9f0563a280525f9d08c12041def0a0f3b2"),
    (319400, "000000000000000021c6052e9becade189495d1c539aa37c58917305fd15f13b"),
    (343185, "0000000000000000072b8bf361d01a6ba7d445dd024203fafc78768ed4368554"),
    (352940, "000000000000000010755df42dba556bb72be6a32f3ce0b6941ce4430152c9ff"),
    (382320, "00000000000000000a8dc6ed5b133d0eb2fd6af56203e4159789b092defd8ab2"),
    (400000, "000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f"),
    (430000, "000000000000000001868b2bb3a285f3cc6b33ea234eb70facf4dcdf22186b87"),
    (460000, "000000000000000000ef751bbce8e744ad303c47ece06c8d863e4d417efc258c"),
    (490000, "000000000000000000de069137b17b8d5a3dfbd5b145b2dcfb203f15d0c4de90"),
    (520000, "0000000000000000000d26984c0229c9f6962dc74db0a6d525f2f1640396f69c"),
    (550000, "000000000000000000223b7a2298fb1c6c75fb0efc28a4c56853ff4112ec6bc9"),
    (560000, "0000000000000000002c7b276daf6efb2b6aa68e2ce3be67ef925b3264ae7122"),
]

# Consensus rule change deployments.
#
# The miner confirmation window is defined as:
#   target proof of work timespan / target proof of work spacing
RuleChangeActivationThreshold = 1916  # 95% of MinerConfirmationWindow
MinerConfirmationWindow = 2016

# Mempool parameters
RelayNonStdTxs = False

# Human-readable part for Bech32 encoded segwit addresses, as defined in
# BIP 173.
Bech32HRPSegwit = "bc"  # always bc for main net

# Address encoding magics
PubKeyHashAddrID = 0x00  # starts with 1
ScriptHashAddrID = 0x05  # starts with 3
PrivateKeyID = 0x80  # starts with 5 (uncompressed) or K (compressed)
WitnessPubKeyHashAddrID = 0x06  # starts with p2
WitnessScriptHashAddrID = 0x0A  # starts with 7Xh

# BIP32 hierarchical deterministic extended key magics
HDPrivateKeyID = (0x0488ADE4).to_bytes(4, byteorder="big")  # starts with xprv
HDPublicKeyID = (0x0488B21E).to_bytes(4, byteorder="big")  # starts with xpub

# BIP44 coin type used in the hierarchical deterministic path for
# address generation.
HDCoinType = 0
