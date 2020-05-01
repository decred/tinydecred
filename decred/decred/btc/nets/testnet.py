"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.

testnet holds testnet parameters. Any values should mirror exactly
https://github.com/btcsuite/btcd/blob/master/chaincfg/params.go
"""

Name = "testnet3"
DefaultPort = "18333"
DNSSeeds = [
    ("testnet-seed.bitcoin.jonasschnelli.ch", True),
    ("testnet-seed.bitcoin.schildbach.de", False),
    ("seed.tbtc.petertodd.org", True),
    ("testnet-seed.bluematt.me", False),
]

# Chain parameters
GenesisHash = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
PowLimit = 2 ^ 224 - 1
PowLimitBits = 0x1D00FFFF
BIP0034Height = (
    21111  # 0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8
)
BIP0065Height = (
    581885  # 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
)
BIP0066Height = (
    330776  # 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
)
CoinbaseMaturity = 100
SubsidyReductionInterval = 210000
TargetTimespan = 60 * 60 * 24 * 14  # 14 days
TargetTimePerBlock = 60 * 10  # 10 minutes
RetargetAdjustmentFactor = 4  # 25% less, 400% more
ReduceMinDifficulty = True
MinDiffReductionTime = 60 * 20  # TargetTimePerBlock * 2
GenerateSupported = False

# Checkpoints ordered from oldest to newest.
Checkpoints = [
    (546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"),
    (100000, "00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e"),
    (200000, "0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2"),
    (300001, "0000000000004829474748f3d1bc8fcf893c88be255e6d7f571c548aff57abf4"),
    (400002, "0000000005e2c73b8ecb82ae2dbc2e8274614ebad7172b53528aba7501f5a089"),
    (500011, "00000000000929f63977fbac92ff570a9bd9e7715401ee96f2848f7b07750b02"),
    (600002, "000000000001f471389afd6ee94dcace5ccc44adc18e8bff402443f034b07240"),
    (700000, "000000000000406178b12a4dea3b27e13b3c4fe4510994fd667d7c1e6a3f4dc1"),
    (800010, "000000000017ed35296433190b6829db01e657d80631d43f5983fa403bfdb4c1"),
    (900000, "0000000000356f8d8924556e765b7a94aaebc6b5c8685dcfa2b1ee8b41acd89b"),
    (1000007, "00000000001ccb893d8a1f25b70ad173ce955e5f50124261bbbc50379a612ddf"),
    (1100007, "00000000000abc7b2cd18768ab3dee20857326a818d1946ed6796f42d66dd1e8"),
    (1200007, "00000000000004f2dc41845771909db57e04191714ed8c963f7e56713a7b6cea"),
    (1300007, "0000000072eab69d54df75107c052b26b0395b44f77578184293bf1bb1dbd9fa"),
]

# Consensus rule change deployments.
#
# The miner confirmation window is defined as:
#   target proof of work timespan / target proof of work spacing
RuleChangeActivationThreshold = 1512  # 75% of MinerConfirmationWindow
MinerConfirmationWindow = 2016

# Mempool parameters
RelayNonStdTxs = True

# Human-readable part for Bech32 encoded segwit addresses, as defined in
# BIP 173.
Bech32HRPSegwit = "tb"  # always tb for test net

# Address encoding magics
PubKeyHashAddrID = 0x6F  # starts with m or n
ScriptHashAddrID = 0xC4  # starts with 2
WitnessPubKeyHashAddrID = 0x03  # starts with QW
WitnessScriptHashAddrID = 0x28  # starts with T7n
PrivateKeyID = 0xEF  # starts with 9 (uncompressed) or c (compressed)

# BIP32 hierarchical deterministic extended key magics
HDPrivateKeyID = (0x04358394).to_bytes(4, byteorder="big")  # starts with tprv
HDPublicKeyID = (0x043587CF).to_bytes(4, byteorder="big")  # starts with tpub

# BIP44 coin type used in the hierarchical deterministic path for
# address generation.
HDCoinType = 1
