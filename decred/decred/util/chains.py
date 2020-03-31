"""
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details
"""

from decred import DecredError
from decred.dcr import account as dcracct, nets as dcrnets


class BipIDs:
    """
    BIP0044 IDs for supported assets.
    """

    decred = dcracct.BIPID


"""IDSymbols converts BIP0044 ID to a lower-case ticker symbol."""
IDSymbols = {
    BipIDs.decred: "dcr",
}


"""
SymbolIDs is a Python dict mapping ticker symbols for supported assets to
their BIP0044 ID.
"""
SymbolIDs = {v: k for k, v in IDSymbols.items()}


"""
AccountConstructors maps the asset's BIP0044 ID to the constructor for the
Account object.
"""
AccountConstructors = {
    BipIDs.decred: dcracct.Account,
}


"""
NetworkParams maps the asset's BIP0044 ID to a dict of network parameters.
"""
NetworkParams = {
    BipIDs.decred: {
        "mainnet": dcrnets.mainnet,
        "testnet3": dcrnets.testnet,
        "simnet": dcrnets.simnet,
    }
}


def parseCoinType(coinType):
    """
    Parse the coin type. If coinType is a string, it will be converted to the
    BIP0044 ID. If it is already an integer, it is returned as is.

    Args:
        coinType (int or str): The asset. BIP0044 ID or ticker symbol.

    Returns:
        int: The BIP0044 ID.
    """
    if isinstance(coinType, str):
        ticker = coinType.lower()
        if ticker not in SymbolIDs:
            raise DecredError(f"ticker symbol {ticker} not found")
        coinType = SymbolIDs[ticker]
    if not isinstance(coinType, int):
        raise DecredError(f"unsupported type for coinType {type(coinType)}")
    return coinType


_chains = {}


def registerChain(coinType, chain):
    """
    Set the app-wide network parameters for a particular asset.

    Args:
        coinType (int or str): The asset. BIP0044 ID or ticker symbol.
        chain (obj): Network parameters.
    """
    _chains[parseCoinType(coinType)] = chain


def chain(coinType):
    """
    Fetch the registered network parameters for an asset.

    Args:
        coinType (int or str): The asset. BIP0044 ID or ticker symbol.

    Returns:
        obj: Network parameters.
    """
    return _chains.get(parseCoinType(coinType))
