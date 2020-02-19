"""
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

from decred import DecredError

from . import mainnet, simnet, testnet


the_nets = {n.Name: n for n in (mainnet, testnet, simnet)}


def parse(name):
    """
    Get the network parameters based on the network name.
    """
    # Set testnet to DCR for now. If more coins are added, a better solution
    # will be needed.
    try:
        return the_nets[name]
    except KeyError:
        raise DecredError(f"unrecognized network name {name}")
