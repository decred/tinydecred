"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details

accounts module
    Mostly account handling, interaction with this package's functions will
    mostly be through the AccountManager.
"""

from decred import DecredError
from decred.crypto import crypto
from decred.util import chains, encode, helpers


EXTERNAL_BRANCH = 0
INTERNAL_BRANCH = 1
ACCOUNT_GAP_LIMIT = 10

DEFAULT_ACCOUNT_NAME = "default"

log = helpers.getLogger("ACCTS")


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


class AccountManager:
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
            signals (Signal): optional. The UI callbacks. Should be
                included if db is specified.
        """
        # The crypto keys are used to decrypt the other keys.
        self.coinType = coinType
        self.coinKeyEnc = coinKeyEnc

        # The Scrypt parameters used to encrypt the crypto keys.
        self.netName = netName
        self.netParams = chains.NetworkParams[self.coinType][self.netName]

        self.watchingOnly = False

        self.node = None
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
        encode.unblobCheck("AccountManager", ver, len(d), {0: 4})

        am = AccountManager(
            coinType=encode.intFromBytes(d[0]),
            coinKeyEnc=encode.ByteArray(d[1]),
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
        return encode.ByteArray(AccountManager.blob(self))

    def load(self, db, signals):
        """
        Set up the database and set the UI signals.

        Args:
            db (database.Bucket): The database bucket.
            signals (Signal): The UI signals.
        """
        blobber = chains.AccountConstructors[self.coinType]
        self.acctDB = db.child("accts", datatypes=("INTEGER", "BLOB"), blobber=blobber)
        self.signals = signals
        blockchain = chains.chain(self.coinType)
        for idx, acct in self.acctDB.items():
            self.accounts[idx] = acct
            db = self.dbForAcctIdx(idx)
            acct.load(self.dbForAcctIdx(idx), blockchain, self.signals)

    def setNode(self, node):
        """
        Set the dcrd connection for the account.

        Args:
            node (LocalNode): A connected LocalNode.
        """
        self.node = node
        for acct in self.accounts.values():
            acct.setNode(node)

    def setRelayFee(self, idx, fee):
        """
        Save the relay fee for account at index.

        Args:
            idx (int): The account's index.
            fee (int): The relay fee in smallest unit/kb.
        """
        acct = self.accounts[idx]
        acct.relayFee = fee
        self.acctDB[idx] = acct

    def coinKey(self, cryptoKey):
        """
        Decrypt the coin-type extended key.

        Args:
            cryptoKey (crypto.SecretKey): The master encryption key.

        Returns:
            ByteArray:
        """
        return crypto.decodeExtendedKey(self.netParams, cryptoKey, self.coinKeyEnc)

    def dbForAcctIdx(self, idx):
        """
        Get the database bucket for the specified index.

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
        acct = createAccount(
            cryptoKey,
            coinExtKey,
            self.coinType,
            idx,
            self.netName,
            acctName,
            db,
            self.signals,
        )
        blockchain = chains.chain(self.coinType)
        acct.load(self.dbForAcctIdx(idx), blockchain, self.signals)
        self.acctDB[idx] = acct
        self.accounts[idx] = acct
        return acct

    def saveAccount(self, idx):
        """
        Save the account at the specified index.

        Args:
            idx: The account index.
        """
        self.acctDB[idx] = self.accounts[idx]

    def account(self, idx):
        """
        Get the account at the provided index.

        Args:
            idx (int): The account index.

        Returns:
            Account: The account at idx.
        """
        return self.accounts[idx]

    def listAccounts(self):
        """
        Get a list of accounts in order of their account index. The index of the
        of the account in the returned list is its BIP-44 account index.

        Returns:
            list(dcr.Account): All known accounts.
        """

        sortedAccts = sorted(self.accounts.items(), key=lambda pair: pair[0])
        if len(sortedAccts) != sortedAccts[-1][0] + 1:
            raise DecredError(
                "account index mismatch. expected last index {} got {}".format(
                    len(sortedAccts) - 1, sortedAccts[-1][0]
                )
            )
        return [a for _, a in sortedAccts]

    def openAccount(self, idx, cryptoKey):
        """
        Open an account.

        Args:
            idx (int): The acccount index, which is its position in the
                accounts list.
            cryptoKey (ByteArray): The master encoding key.

        Returns:
            Account: The open account.
        """
        acct = self.accounts[idx]
        acct.unlock(cryptoKey)
        return acct

    def discover(self, cryptoKey):
        """
        Discover accounts up to the account gap limit. If an account is
        discovered, all accounts up to and including the discovered account's
        index will be created.

        Args:
            cryptoKey (ByteArray): The master encoding key.
        """
        coinExtKey = self.coinKey(cryptoKey)
        blockchain = chains.chain(self.coinType)
        lastSeenIdx = len(self.acctDB) - 1
        idx = lastSeenIdx + 1
        acctConstructor = chains.AccountConstructors[self.coinType]
        while True:
            acctKeyPriv = coinExtKey.deriveAccountKey(idx)
            acctKeyPub = acctKeyPriv.neuter()
            if acctConstructor.txsExistForKey(acctKeyPub, blockchain):
                # Add accounts up to the newly seen index.
                log.info(f"account discovered at index {idx}")
                while len(self.accounts) <= idx:
                    self.addAccount(cryptoKey, f"Account {len(self.accounts)}")
                lastSeenIdx = idx
            idx += 1
            if idx - lastSeenIdx > ACCOUNT_GAP_LIMIT:
                break


def createNewAccountManager(root, cryptoKey, coinType, netParams, db):
    """
    Create a new account manager and a set of BIP0044 keys for creating
    accounts. The zeroth account is created for the provided network parameters.

    Args:
        root (crypto.ExtendedKey): The wallet key.
        cryptoKey (crypto.SecretKey): The master encryption key.
        netParams (module): Network parameters.

    Returns:
        AccountManager: An initialized account manager.
    """
    coinKey = root.deriveCoinTypeKey(netParams)
    coinKeyEnc = crypto.encrypt(cryptoKey, coinKey.serialize())

    manager = AccountManager(
        coinType=chains.parseCoinType(coinType),
        coinKeyEnc=coinKeyEnc,
        netName=netParams.Name,
        db=db,
    )
    manager.addAccount(cryptoKey, DEFAULT_ACCOUNT_NAME)
    return manager


def createAccount(
    cryptoKey, coinExtKey, coinType, acctIdx, netName, acctName, db, signals
):
    # Create the zeroth account.
    # Derive the account key for the first account according to BIP0044.
    acctKeyPriv = coinExtKey.deriveAccountKey(acctIdx)

    # Ensure the branch keys can be derived for the provided seed according
    # to BIP0044.
    checkBranchKeys(acctKeyPriv)
    acctKeyPub = acctKeyPriv.neuter()
    pubKeyEncrypted = crypto.encrypt(cryptoKey, acctKeyPub.serialize())
    privKeyEncrypted = crypto.encrypt(cryptoKey, acctKeyPriv.serialize())
    constructor = chains.AccountConstructors[coinType]
    blockchain = chains.chain(coinType)
    account = constructor(
        acctIdx,
        pubKeyEncrypted,
        privKeyEncrypted,
        acctName,
        netName,
        db,
        blockchain,
        signals,
    )
    # Open the account.
    account.unlock(cryptoKey)
    # Create the first payment address.
    account.generateGapAddresses()
    # Close the account to zero the key.
    account.lock()
    return account
