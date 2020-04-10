"""
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

from decred import DecredError

from . import mainnet, simnet, testnet


the_nets = {n.Name: n for n in (mainnet, testnet, simnet)}
if "testnet3" in the_nets:
    the_nets["testnet"] = the_nets["testnet3"]


DcrdPorts = {
    mainnet.Name: "9109",
    testnet.Name: "19109",
    simnet.Name: "19556",
}


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


def normalizeName(netName):
    """
    Remove the numerals from testnet.

    Args:
        netName (string): The raw network name.

    Returns:
        string: The network name with numerals stripped.
    """
    return "testnet" if "testnet" in netName else netName
