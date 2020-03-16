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


def checkSeedLength(length):
    """
    Check that seed length is correct.

    Args:
        length int: the seed length to be checked.

    Raises:
        DecredError if length is not between MinSeedBytes and MaxSeedBytes
        included.
    """
    if length < MinSeedBytes or length > MaxSeedBytes:
        raise DecredError(f"Invalid seed length {length}")


def generateSeed(length=MaxSeedBytes):
    """
    Generate a cryptographically-strong random string of the given length.

    Raises:
        DecredError if length is not between MinSeedBytes and MaxSeedBytes
        included.
    """
    checkSeedLength(length)
    return os.urandom(length)


def newHashRaw():
    """
    Generate a random hash of HASH_SIZE length as a string.
    """
    return generateSeed(HASH_SIZE)


def newHash():
    """
    Generate a random hash of HASH_SIZE length as a ByteArray.
    """
    return ByteArray(newHashRaw())


def newKeyRaw():
    """
    Generate a random key of KEY_SIZE length as a string.
    """
    return generateSeed(KEY_SIZE)


def newKey():
    """
    Generate a random key of KEY_SIZE length as a ByteArray.
    """
    return ByteArray(newKeyRaw())
