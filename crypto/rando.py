"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

import os

MinSeedBytes = 16  # 128 bits
MaxSeedBytes = 64  # 512 bits


def generateSeed(length=MaxSeedBytes):
    assert length >= MinSeedBytes and length <= MaxSeedBytes
    return os.urandom(length)
