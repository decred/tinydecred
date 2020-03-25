"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details
"""

from pathlib import Path

from decred import DecredError
from decred.crypto import crypto, mnemonic, rando
from decred.dcr import nets
from decred.dcr.dcrdata import DcrdataBlockchain
from decred.util import chains, database, encode, helpers
from decred.util.helpers import mkdir

from . import accounts


log = helpers.getLogger("WLLT")

BipIDs = chains.BipIDs


class DBKeys:
    cryptoKey = "cryptoKey".encode("utf-8")
    root = "root".encode("utf-8")
    keyParams = "keyParams".encode("utf-8")


class Wallet:
    """
    Wallet is a wallet. An application would use a Wallet to create and
    manager addresses and funds and to interact with various blockchains.
    Ideally, blockchain interactions are always handled through interfaces
    passed as arguments, so Wallet has no concept of full node, SPV node, light
    wallet, etc., just data senders and sources.

    A new Wallet is not typically created directly, but through the static
    methods Wallet.create and Wallet.createFromMnemonic.
    """

    def __init__(self, path):
        """
        Args:
            path (str): The path to the wallet database.
        """
        self.db = database.KeyValueDatabase(path)
        self.masterDB = self.db.child("master", blobber=encode.ByteArray)
        self.coinDB = self.db.child(
            "accts", datatypes=("INTEGER", "BLOB"), blobber=accounts.AccountManager
        )
        self.keyParams = None
        self.selectedAccount = None
        self.openAccount = None
        self.mgrCache = {}
        # The best block.
        self.users = 0

    def initialize(self, seed, pw, netParams):
        """
        Initialize the wallet.

        Args:
            seed (bytes-like): The wallet seed.
            pw   (bytes-like): The wallet password, UTF-8 encoded.
            netParams (module): Network parameters.
        """
        pwKey = crypto.SecretKey(pw)
        cryptoKey = rando.newKey()
        root = crypto.ExtendedKey.new(seed)
        self.masterDB[DBKeys.cryptoKey] = pwKey.encrypt(cryptoKey)
        self.masterDB[DBKeys.root] = root.serialize()
        self.masterDB[DBKeys.keyParams] = crypto.ByteArray(pwKey.params().serialize())
        db = self.coinDB.child(str(BipIDs.decred), table=False)
        acctManager = accounts.createNewAccountManager(
            root, cryptoKey, "dcr", netParams, db
        )
        self.coinDB[BipIDs.decred] = acctManager

    @staticmethod
    def create(path, password, netParams):
        """
        Create a wallet, locked by `password`. The seed will be randomly
        generated.

        Args:
            path (str): Filepath to store wallet.
            password (str): User provided password. The password will be used to
                both decrypt the wallet and unlock any accounts created.
            netParams (module): Network parameters.

        Returns:
            list(str): A mnemonic seed. Only retured when the caller does not
                provide a seed.
            Wallet: An initialized wallet with a single Decred account.
        """
        if len(password) == 0:
            raise DecredError("empty password not allowed")
        seed = rando.newKeyRaw()
        wallet = Wallet(path)
        wallet.initialize(seed, password.encode(), netParams)
        words = mnemonic.encode(seed)
        return words, wallet

    @staticmethod
    def createFromMnemonic(words, path, password, netParams):
        """
        Creates the wallet from the mnemonic seed.

        Args:
            words (list(str)): Mnemonic seed. Assumed to be PGP words.
            path (str): Filepath to store wallet.
            password (str): User password. Passed to Wallet.initialize.

        Returns:
            Wallet: A wallet initialized from the seed parsed from `words`.
        """
        decoded = mnemonic.decode(words)
        cksum = decoded[-1]
        userSeed = decoded[:-1]
        cs = crypto.sha256ChecksumByte(userSeed.b)
        if cs != cksum:
            raise DecredError("bad checksum %r != %r" % (cs, cksum))
        wallet = Wallet(path)
        wallet.initialize(userSeed.b, password.encode(), netParams)
        userSeed.zero()
        return wallet

    def cryptoKey(self, password):
        """
        Create the SecretKey for the password.

        Args:
            password (str): The wallet password.

        Returns:
            ByteArray: The master encoding key.
        """
        if not self.keyParams:
            self.keyParams = crypto.KDFParams.unblob(self.masterDB[DBKeys.keyParams].b)
        pwKey = crypto.SecretKey.rekey(password.encode(), self.keyParams)
        return pwKey.decrypt(self.masterDB[DBKeys.cryptoKey])

    def accountManager(self, coinType, signals):
        coinType = chains.parseCoinType(coinType)
        if coinType in self.mgrCache:
            return self.mgrCache[coinType]
        acctMgr = self.coinDB[coinType]
        acctDB = self.coinDB.child(str(coinType), table=False)
        acctMgr.load(acctDB, signals)
        self.mgrCache[coinType] = acctMgr
        return acctMgr


# SimpleWallet code.


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
    netDir = Path(base) / network
    dbPath = netDir / "wallet.db"
    dcrPath = netDir / "dcr.db"
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
        if not Path(netDir).exists():
            mkdir(netDir)
        dcrdataDB = database.KeyValueDatabase(dcrPath)
        # The initialized DcrdataBlockchain will not be connected, as that is a
        # blocking operation. It will be called when the wallet is open.
        dcrdataURL = DCRDATA_PATHS[netParams.Name]
        self.dcrdata = DcrdataBlockchain(dcrdataDB, netParams, dcrdataURL)
        chains.registerChain("dcr", self.dcrdata)
        walletExists = Path(dbPath).is_file()
        if not walletExists and not allowCreate:
            raise DecredError("Wallet does not exist at %s", dbPath)

        super().__init__(dbPath)
        # words is only set the first time a wallet is created.
        if not walletExists:
            seed = rando.newKeyRaw()
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
        if Path(dbPath).is_file():
            raise DecredError("wallet already exists at %s" % dbPath)
        wallet = SimpleWallet(walletDir, pw, network, signals, True)
        words = wallet.words
        wallet.words.clear()
        return wallet, words

    def close(self):
        self.dcrdata.close()
