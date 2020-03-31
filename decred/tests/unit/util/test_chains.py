"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.util import chains


def test_parseCoinType():
    with pytest.raises(DecredError):
        chains.parseCoinType("not_a_coin")

    assert chains.parseCoinType("DCR") == 42
    assert chains.parseCoinType(42) == 42
    assert chains.parseCoinType(-1) == -1

    with pytest.raises(DecredError):
        chains.parseCoinType(None)
