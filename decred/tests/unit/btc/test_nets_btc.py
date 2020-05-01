"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.btc import nets


def test_nets():
    assert nets.parse("mainnet") is nets.mainnet

    assert nets.normalizeName("testnet3") == "testnet"

    with pytest.raises(DecredError):
        nets.parse("nonet")
