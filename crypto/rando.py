"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""
import os
from tinydecred.pydecred import constants as C


def generateSeed(length=C.MaxSeedBytes):
    assert length >= C.MinSeedBytes and length <= C.MaxSeedBytes
    return os.urandom(length)
