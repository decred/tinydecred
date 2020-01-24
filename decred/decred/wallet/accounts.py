"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

accounts module
    Mostly account handling, interaction with this package's functions will
    mostly be through the AccountManager.
    The tinycrypto package relies heavily on the lower-level crypto modules.
"""

from decred.crypto import crypto
from decred.util import chains, encode, helpers


ByteArray = encode.ByteArray
BuildyBytes = encode.BuildyBytes

EXTERNAL_BRANCH = 0
INTERNAL_BRANCH = 1

DEFAULT_ACCOUNT_NAME = "default"

log = helpers.getLogger("TCRYP")  # , logLvl=0)


def checkBranchKeys(acctKey):
    """
    Try to raise an exception.
    checkBranchKeys ensures deriving the extended keys for the internal and
    external branches given an account key does not result in an invalid child
    error which means the chosen seed is not usable. This conforms to the
    hierarchy described by BIP0044 so long as the account key is already derived
    accordingly.

    In particular this is the hierarchical deterministic extended key path:
      m/44'/<coin type>'/<account>'/<branch>

    The branch is 0 for external addresses and 1 for internal addresses.

    Args:
        acctKey (crypto.ExtendedKey): An account's extended key.
    """
    # Derive the external branch as the first child of the account key.
    acctKey.child(EXTERNAL_BRANCH)

    # Derive the interal branch as the second child of the account key.
    acctKey.child(INTERNAL_BRANCH)


class AccountManager(object):
    """
    The AccountManager provides generation, organization, and other management
    of Accounts.
    """

    def __init__(
        self, coinType, coinKeyEnc, netName, db=None, signals=None,
    ):
        """
        Args:
            coinType (int): The BIP-0044 coin type.
            coinKeyEnc (ByteArray): The encrypted, serialized extended key.
            netName (string): Network name. "mainnet", "testnet", etc.
            db (database.Bucket): optional. The database bucket. If specified,
                the db will be loaded.
            signals (api.Signals): optional. The UI callbacks. Should be
                included if db is specified.
        """
        # The crypto keys are used to decrypt the other keys.
        self.coinType = coinType
        self.coinKeyEnc = coinKeyEnc

        # The Scrypt parameters used to encrypt the crypto keys.
        self.netName = netName
        self.net = self.netParams()

        self.watchingOnly = False

        self.acctDB = None
        self.signals = None
        self.accounts = {}
        if db is not None:
            self.load(db, signals)

    @staticmethod
    def blob(bal):
        """Satisfies the encode.Blobber API"""
        return (
            encode.BuildyBytes(0)
            .addData(bal.coinType)
            .addData(bal.coinKeyEnc)
            .addData(bal.netName.encode("utf-8"))
            .addData(encode.boolToBytes(bal.watchingOnly))
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("invalid AccountManager version %d" % ver)
        if len(d) != 4:
            raise AssertionError(
                "expected 4 pushes for AccountManager, got %d" % len(d)
            )

        am = AccountManager(
            coinType=encode.intFromBytes(d[0]),
            coinKeyEnc=ByteArray(d[1]),
            netName=d[2].decode("utf-8"),
        )
        am.watchingOnly = encode.boolFromBytes(d[3])
        return am

    def serialize(self):
        """
        Serialize the AccountManager.

        Returns:
            ByteArray: The serialized AccountManager.
        """
        return ByteArray(AccountManager.blob(self))

    def netParams(self):
        """
        Get the network parameters for the account.

        Returns:
            object: The network parameters.
        """
        return chains.NetworkParams[self.coinType][self.netName]

    def load(self, db, signals):
        """
        Set up the database and set the UI signals.

        Args:
            db (database.Bucket): The database bucket.
            signals (api.Signals): The UI signals.
        """
        blobber = chains.AccountConstructors[self.coinType]
        self.acctDB = db.child("accts", datatypes=("INTEGER", "BLOB"), blobber=blobber)
        self.signals = signals

    def coinKey(self, cryptoKey):
        """
        Decrypt the coin-type extended key.

        Args:
            cryptoKey (crypto.SecretKey): The master encryption key.

        Returns:
            ByteArray:
        """
        return crypto.decodeExtendedKey(self.net, cryptoKey, self.coinKeyEnc)

    def dbForAcctIdx(self, idx):
        """
        Get the databse bucket for the specified index.

        Args:
            idx (int): The account index.

        Returns:
            database.Bucket: The account bucket.
        """
        return self.acctDB.child(str(idx), table=False)

    def addAccount(self, cryptoKey, acctName):
        """
        Add a new account and return its index.

        Args:
            cryptoKey (ByteArray): The master encoding key.
            acctName: A name for the account.

        Returns:
            Account: The account.
        """
        idx = len(self.acctDB)
        coinExtKey = self.coinKey(cryptoKey)
        db = self.dbForAcctIdx(idx)
        account = createAccount(
            cryptoKey,
            coinExtKey,
            self.coinType,
            idx,
            self.netName,
            acctName,
            db,
            self.signals,
        )
        self.acctDB[idx] = account
        return account

    def account(self, idx):
        """
        Get the account at the provided index.

        Args:
            idx (int): The account index.

        Returns:
            Account: The account at idx.
        """
        account = self.acctDB[idx]
        account.load(self.dbForAcctIdx(idx))
        self.accounts[idx] = account
        return account

    def openAccount(self, acct, cryptoKey):
        """
        Open an account.

        Args:
            acct (int): The acccount index, which is its position in the
                accounts list.
            cryptoKey (ByteArray): The master encoding key.

        Returns:
            Account: The open account.
        """
        # Retreive and open the account.
        account = self.accounts[acct] if acct in self.accounts else self.account(acct)
        account.open(cryptoKey, chains.chain(self.coinType), self.signals)
        return account


def createNewAccountManager(root, cryptoKey, coinType, chainParams, db):
    """
    Create a new account manager and a set of BIP0044 keys for creating
    accounts. The zeroth account is created for the provided network parameters.

    Args:
        root (crypto.ExtendedKey): The wallet key.
        cryptoKey (crypto.SecretKey): The master encryption key.
        chainParams (object): Network parameters.

    Returns:
        AccountManager: An initialized account manager.
    """
    coinKey = root.deriveCoinTypeKey(chainParams)
    coinKeyEnc = crypto.encrypt(cryptoKey, coinKey.serialize())

    manager = AccountManager(
        coinType=chains.parseCoinType(coinType),
        coinKeyEnc=coinKeyEnc,
        netName=chainParams.Name,
        db=db,
    )
    manager.addAccount(cryptoKey, DEFAULT_ACCOUNT_NAME)
    return manager


def createAccount(
    cryptoKey, coinExtKey, coinType, acct, netName, acctName, db, signals
):
    # Create the zeroth account132
    # Derive the account key for the first account according to BIP0044.
    acctKeyPriv = coinExtKey.deriveAccountKey(acct)

    # Ensure the branch keys can be derived for the provided seed according
    # to BIP0044.
    checkBranchKeys(acctKeyPriv)
    acctKeyPub = acctKeyPriv.neuter()
    pubKeyEncrypted = crypto.encrypt(cryptoKey, acctKeyPub.serialize())
    privKeyEncrypted = crypto.encrypt(cryptoKey, acctKeyPriv.serialize())
    constructor = chains.AccountConstructors[coinType]
    account = constructor(pubKeyEncrypted, privKeyEncrypted, acctName, netName, db)
    # Open the account.
    account.open(cryptoKey, chains.chain(coinType), signals)
    # Create the first payment address.
    account.generateGapAddresses()
    # Close the account to zero the key.
    account.close()
    return account
