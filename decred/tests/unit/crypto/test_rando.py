"""
Copyright (c) 2020, The Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.crypto import rando


def test_checkSeedLength():
    with pytest.raises(DecredError):
        rando.checkSeedLength(rando.MinSeedBytes - 1)
    assert rando.checkSeedLength(rando.MinSeedBytes) is None
    assert rando.checkSeedLength(rando.HASH_SIZE) is None
    assert rando.checkSeedLength(rando.KEY_SIZE) is None
    assert rando.checkSeedLength(rando.MaxSeedBytes) is None
    with pytest.raises(DecredError):
        rando.checkSeedLength(rando.MaxSeedBytes + 1)
