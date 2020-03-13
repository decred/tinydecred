"""
Copyright (c) 2020, The Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.crypto import rando


def test_checkSeed():
    with pytest.raises(DecredError):
        rando.checkSeed(rando.MinSeedBytes - 1)
    assert rando.checkSeed(rando.MinSeedBytes) is None
    assert rando.checkSeed(rando.HASH_SIZE) is None
    assert rando.checkSeed(rando.KEY_SIZE) is None
    assert rando.checkSeed(rando.MaxSeedBytes) is None
    with pytest.raises(DecredError):
        rando.checkSeed(rando.MaxSeedBytes + 1)
