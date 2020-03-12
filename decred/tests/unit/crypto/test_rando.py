"""
Copyright (c) 2020, The Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.crypto import rando


def test_checkSeed():
    with pytest.raises(DecredError):
        rando.checkSeed(1)
