"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-20, The Decred developers
See LICENSE for details
"""

import os

from decred import DecredError
from decred.util.encode import ByteArray


KEY_SIZE = 32
HASH_SIZE = 32

MinSeedBytes = 16  # 128 bits
MaxSeedBytes = 64  # 512 bits


def checkSeed(length):
    if length < MinSeedBytes or length > MaxSeedBytes:
        raise DecredError(f"Invalid seed length {length}")


def generateSeed(length=MaxSeedBytes):
    checkSeed(length)
    return os.urandom(length)


def newHashRaw():
    return generateSeed(HASH_SIZE)


def newHash():
    return ByteArray(newHashRaw())


def newKeyRaw():
    return generateSeed(KEY_SIZE)


def newKey():
    return ByteArray(newKeyRaw())
