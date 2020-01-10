from tinydecred import config
from tinydecred.pydecred import account as dcracct, nets as dcrnets

cfg = config.load()


class BipIDs:
    decred = dcracct.BIPID


IDSymbols = {
    BipIDs.decred: "dcr",
}

SymbolIDs = {v: k for k, v in IDSymbols.items()}


AccountConstructors = {
    BipIDs.decred: dcracct.Account,
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
        if ticker not in SymbolIDs:
            raise AssertionError("ticker symbol %d not found" % ticker)
        coinType = SymbolIDs[ticker]
    if not isinstance(coinType, int):
        raise AssertionError("unsupported type for coinType %s" % type(coinType))
    return coinType


_chains = {}


def registerChain(coinType, chain):
    _chains[parseCoinType(coinType)] = chain


def chain(coinType):
    coinType = parseCoinType(coinType)
    return _chains[coinType] if coinType in _chains else None
