"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import pytest

from decred.dcr import mainnet, nets


def test_nets():
    assert nets.parse("mainnet") is mainnet

    with pytest.raises(ValueError):
        nets.parse("nonet")
