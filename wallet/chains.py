from tinydecred import config
from tinydecred.pydecred import account as dcracct, nets as dcrnets

cfg = config.load()


class BipIDs:
    decred = 42


IDSymbols = {
    BipIDs.decred: "dcr",
}

SymbolIDs = {v: k for k, v in IDSymbols.items()}


AccountConstructors = {
    BipIDs.decred: dcracct.DecredAccount,
}

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
    """
    if isinstance(coinType, str):
        ticker = coinType.lower()
        assert ticker in SymbolIDs, "ticker symbol not found"
        coinType = SymbolIDs[ticker]
    assert isinstance(coinType, int)
    return coinType


_chains = {}


def registerChain(coinType, chain):
    _chains[parseCoinType(coinType)] = chain


def chain(coinType):
    coinType = parseCoinType(coinType)
    assert coinType in _chains, "coin " + str(coinType) + " not registered"
    return _chains[coinType]
