"""
Copyright (c) 2020, The Decred developers
See LICENSE for details.
"""

from decred import DecredError

from . import mainnet, regtest, simnet, testnet


the_nets = {n.Name: n for n in (mainnet, testnet, simnet, regtest)}
if "testnet3" in the_nets:
    the_nets["testnet"] = the_nets["testnet3"]
if "regtest" in the_nets:
    the_nets["regnet"] = the_nets["regtest"]


RPCPorts = {
    mainnet.Name: "8332",
    testnet.Name: "18332",
    simnet.Name: "18554",
    regtest.Name: "18443",
}


def parse(name):
    """
    Get the network parameters based on the network name.
    """
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
