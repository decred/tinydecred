"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

import os


MinSeedBytes = 16  # 128 bits
MaxSeedBytes = 64  # 512 bits


def generateSeed(length=MaxSeedBytes):
    if length < MinSeedBytes or length > MaxSeedBytes:
        raise AssertionError("invalid seed length %d" % length)
    return os.urandom(length)
