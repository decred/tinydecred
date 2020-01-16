"""
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

from . import mainnet, testnet, simnet


mainnet = mainnet
testnet = testnet
simnet = simnet


def parse(name):
    """
    Get the network parameters based on the network name.

    Args:
        acct (Account): An account with a properly set coinID and netID.
    """
    # Set testnet to DCR for now. If more coins are added, a better solution
    # will be needed.
    for net in (mainnet, simnet, testnet):
        if net.Name == name:
            return net
    raise Exception("unrecognized network name %s" % name)
