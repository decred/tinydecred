"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2020, The Decred developers
See LICENSE for details
"""

import os

from decred import DecredError
from decred.crypto import crypto, mnemonic, rando
from decred.dcr import nets
from decred.dcr.dcrdata import DcrdataBlockchain
from decred.util import chains, database
from decred.util.helpers import mkdir
from decred.wallet.wallet import Wallet


class DefaultSignals:
    """DefaultSignals prints the balance to stdout."""

    @staticmethod
    def balance(b):
        print(repr(b))


def paths(base, network):
    """
    Get the paths for the network directory, the wallet database file, and the
    blockchain database file.
    """
    netDir = os.path.join(base, network)
    dbPath = os.path.join(netDir, "wallet.db")
    dcrPath = os.path.join(netDir, "dcr.db")
    return netDir, dbPath, dcrPath


DCRDATA_PATHS = {
    "mainnet": "https://explorer.dcrdata.org/",
    "testnet3": "https://testnet.dcrdata.org/",
    "simnet": "http://localhost:17779",
}


class SimpleWallet(Wallet):
    """
    SimpleWallet is a single-account Decred wallet.
    """

    def __init__(self, walletDir, pw, network, signals=None, allowCreate=False):
        """
        Args:
            dir (str): A directory for wallet database files.
            pw (str): The user password.
            network (str): The network name.
            signals (Signals): A signal processor.
        """
        signals = signals if signals else DefaultSignals
        netParams = nets.parse(network)
        netDir, dbPath, dcrPath = paths(walletDir, netParams.Name)
        if not os.path.exists(netDir):
            mkdir(netDir)
        dcrdataDB = database.KeyValueDatabase(dcrPath)
        # The initialized DcrdataBlockchain will not be connected, as that is a
        # blocking operation. It will be called when the wallet is open.
        dcrdataURL = DCRDATA_PATHS[netParams.Name]
        self.dcrdata = DcrdataBlockchain(dcrdataDB, netParams, dcrdataURL)
        chains.registerChain("dcr", self.dcrdata)
        walletExists = os.path.isfile(dbPath)
        if not walletExists and not allowCreate:
            raise DecredError("Wallet does not exist at %s", dbPath)

        super().__init__(dbPath)
        # words is only set the first time a wallet is created.
        if not walletExists:
            seed = rando.generateSeed(crypto.KEY_SIZE)
            self.initialize(seed, pw.encode(), netParams)
            self.words = mnemonic.encode(seed)

        cryptoKey = self.cryptoKey(pw)
        acctMgr = self.accountManager(chains.BipIDs.decred, signals)
        self.account = acctMgr.openAccount(0, cryptoKey)
        self.account.sync()

    def __getattr__(self, name):
        """Delegate unknown methods to the account."""
        return getattr(self.account, name)

    @staticmethod
    def create(walletDir, pw, network, signals=None):
        """
        Create a new wallet. Will not overwrite an existing wallet file. All
        arguments are the same as the SimpleWallet constructor.
        """
        netParams = nets.parse(network)
        _, dbPath, _ = paths(walletDir, netParams.Name)
        if os.path.exists(dbPath):
            raise DecredError("wallet already exists at %s", dbPath)
        wallet = SimpleWallet(walletDir, pw, network, signals, True)
        words = wallet.words
        wallet.words.clear()
        return wallet, words

    def close(self):
        self.dcrdata.close()
