"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import pytest

from decred.dcr import nets


def test_nets():
    assert nets.parse("mainnet") is nets.mainnet

    with pytest.raises(ValueError):
        nets.parse("nonet")
