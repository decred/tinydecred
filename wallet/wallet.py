"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""
from threading import Lock as Mutex
from tinydecred.util import helpers, encode
from tinydecred.util.database import KeyValueDatabase
from tinydecred.crypto import crypto, mnemonic, rando
from tinydecred.wallet import accounts, chains
from tinydecred import config

cfg = config.load()

log = helpers.getLogger("WLLT")  # , logLvl=0)

CHECKPHRASE = "tinydecred".encode("utf-8")

BipIDs = chains.BipIDs


class DBKeys:
    cryptoKey = "cryptoKey".encode("utf-8")
    root = "root".encode("utf-8")
    checkKey = "checkKey".encode("utf-8")
    keyParams = "keyParams".encode("utf-8")


class Wallet(object):
    """
    Wallet is a wallet. An application would use a Wallet to create and
    manager addresses and funds and to interact with various blockchains.
    Ideally, blockchain interactions are always handled through interfaces
    passed as arguments, so Wallet has no concept of full node, SPV node, light
    wallet, etc., just data senders and sources.

    The Wallet is not typically created directly, but through its static methods
    `openFile` and `create`.

    The wallet has a mutex lock to sequence operations. The easiest way to use
    wallet is with the `with` statement, i.e.
        ```
        sender = lambda h: dcrdata.insight.api.tx.send.post({"rawtx": h})
        with wallet.open("dcr", ...) as w:
            w.sendToAddress(v, addr, sender)
        ```
    If the wallet is used in this way, the mutex will be locked and unlocked
    appropriately.
    """

    def __init__(self, path):
        """
        Args:
            path (str): The path to the wallet database.
        """
        self.db = KeyValueDatabase(path)
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
        # User provided callbacks for certain events.
        self.mtx = Mutex()

    def initialize(self, seed, pw):
        """
        Initialize the wallet.

        Args:
            seed (bytes-like): The wallet seed.
            pw   (bytes-like): The wallet password, UTF-8 encoded.
        """
        pwKey = crypto.SecretKey(pw)
        cryptoKey = encode.ByteArray(rando.generateSeed(crypto.KEY_SIZE))
        root = crypto.ExtendedKey.new(seed)
        self.masterDB[DBKeys.cryptoKey] = pwKey.encrypt(cryptoKey)
        self.masterDB[DBKeys.root] = root.serialize()
        self.masterDB[DBKeys.checkKey] = pwKey.encrypt(CHECKPHRASE)
        self.masterDB[DBKeys.keyParams] = crypto.ByteArray(pwKey.params().serialize())
        db = self.coinDB.child(str(BipIDs.decred), table=False)
        acctManager = accounts.createNewAccountManager(
            root, cryptoKey, "dcr", cfg.net, db
        )
        self.coinDB[BipIDs.decred] = acctManager

    @staticmethod
    def create(path, password):
        """
        Create a wallet, locked by `password`. The seed will be randomly
        generated.

        Args:
            path (str): Filepath to store wallet.
            password (str): User provided password. The password will be used to
                both decrypt the wallet, and unlock any accounts created.
            chain (object): Network parameters for the zeroth account ExtendedKey.

        Returns:
            Wallet: An initialized wallet with a single Decred account.
            list(str): A mnemonic seed. Only retured when the caller does not
                provide a seed.
        """
        assert len(password) > 0
        seed = rando.generateSeed(crypto.KEY_SIZE)
        wallet = Wallet(path)
        wallet.initialize(seed, password.encode())
        words = mnemonic.encode(seed)
        return words, wallet

    @staticmethod
    def createFromMnemonic(words, path, password):
        """
        Creates the wallet from the mnemonic seed.

        Args:
            words (list(str)): Mnemonic seed. Assumed to be PGP words.
            path (str): Filepath to store wallet.
            password (str): User password. Passed to Wallet.create.

        Returns:
            Wallet: A wallet initialized from the seed parsed from `words`.
        """
        decoded = mnemonic.decode(words)
        cksum = decoded[-1]
        userSeed = decoded[:-1]
        cs = crypto.sha256ChecksumByte(userSeed.b)
        if cs != cksum:
            raise Exception("bad checksum %r != %r" % (cs, cksum))
        wallet = Wallet(path)
        wallet.initialize(userSeed.b, password.encode())
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
        checkPhrase = pwKey.decrypt(self.masterDB[DBKeys.checkKey])
        assert checkPhrase == CHECKPHRASE
        return pwKey.decrypt(self.masterDB[DBKeys.cryptoKey])

    @staticmethod
    def openFile(filepath, password, signals):
        """
        Just checks that the provided password is correct, raising an exception
        on error.

        Args:
            password (string): The wallet password.
        """
        wallet = Wallet(filepath)
        # check that the password is correct.
        wallet.cryptoKey(password).zero()
        # Open the zeroth account. This will likely change.
        wallet.open("dcr", 0, password, signals)
        return wallet

    def accountManager(self, coinType, signals):
        coinType = chains.parseCoinType(coinType)
        if coinType in self.mgrCache:
            return self.mgrCache[coinType]
        acctMgr = self.coinDB[coinType]
        acctDB = self.coinDB.child(str(coinType), table=False)
        acctMgr.load(acctDB, signals)
        self.mgrCache[coinType] = acctMgr
        return acctMgr

    def open(self, coinType, acct, password, signals):
        """
        Open an account. The Wallet is returned so that it can be used in
            `with ... as` block for context management.

        Args:
            coinType (str|int): Asset identifier.
            acct (int): The account number to open.
            password (str): Wallet password. Should be the same as used to open
                the wallet.
            signals (object): An api.Signals.

        Returns:
            Wallet: The wallet with the default account open.
        """

        cryptoKey = self.cryptoKey(password)
        acctManager = self.accountManager(coinType, signals)
        self.selectedAccount = self.openAccount = acctManager.openAccount(
            acct, cryptoKey
        )
        return self

    def lock(self):
        """
        Lock the wallet for use. The preferred way to lock and unlock the wallet
        is indirectly through a contextual `with ... as` block.
        """
        self.mtx.acquire()

    def unlock(self):
        """
        Unlock the wallet for use. The preferred way to lock and unlock the
        wallet is indirectly through a contextual `with ... as` block.
        """
        self.mtx.release()

    def __enter__(self):
        """
        For use in a `with ... as` block. The returned value is assigned to the
        `as` variable.
        """
        # The user count must be incremented before locking. In python, simple
        # assignment is thead-safe, but compound assignment, e.g. +=, is not.
        u = self.users
        self.users = u + 1
        self.lock()
        return self

    def __exit__(self, xType, xVal, xTB):
        """
        Executed at the end of the `with ... as` block. Decrement the user
        count and close the wallet if nobody is waiting.
        The arguments are provided by Python, and have information about any
        exception encountered and a traceback.
        """
        u = self.users
        self.users = u - 1
        self.unlock()
        if u == 1:
            self.close()

    def close(self):
        """
        Save the wallet and close any open account.
        """
        if self.openAccount:
            self.openAccount.close()
            self.openAccount = None

    def getNewAddress(self):
        """
        Get the next unused external address.

        Returns:
            str: The next unused external address.
        """
        return self.selectedAccount.nextExternalAddress()

    def currentAddress(self):
        """
        Gets the payment address at the cursor.

        Returns:
            str: The current external address.
        """
        return self.selectedAccount.currentAddress()

    def balance(self):
        """
        Get the balance of the currently selected account.

        Returns:
            Balance: The current account's Balance object.
        """
        return self.selectedAccount.balance

    def sync(self):
        """
        Synchronize the UTXO set with the server. This should be the first
        action after the account is opened or changed.

        Returns:
            bool: `True` if no exceptions were encountered.
        """
        # send the initial balance. This was the balance the last time the
        # wallet was saved, but may be innacurate until sync in complete.
        self.openAccount.sync()
        return True
