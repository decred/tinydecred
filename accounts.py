"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

accounts module
    Mostly account handling, interaction with this package's functions will 
    mostly be through the AccountManager.
    The tinycrypto package relies heavily on the lower-level crypto modules.
"""
import unittest
import hashlib
from tinydecred.util import tinyjson, helpers
from tinydecred import api
from tinydecred.pydecred import nets, constants as DCR
from tinydecred.crypto import crypto
from tinydecred.crypto.rando import generateSeed
from tinydecred.crypto.bytearray import ByteArray


EXTERNAL_BRANCH = 0
INTERNAL_BRANCH = 1
MASTER_KEY = b"Bitcoin seed"
MAX_SECRET_INT = 115792089237316195423570985008687907852837564279074904382605163141518161494337
SALT_SIZE = 32
DEFAULT_ACCOUNT_NAME = "default"

CrazyAddress = "CRAZYADDRESS"

log = helpers.getLogger("TCRYP") # , logLvl=0)

class CoinSymbols:
    decred = "dcr"

def setNetwork(acct):
    """
    Set the account network parameters based on the coin-type and network name.
    If the network does not match the loaded configuration network(s), raises an
    exception.

    Args:
        acct (Account): An account with a properly set coinID and netID.
    """
    # Set testnet to DCR for now. If more coins are added, a better solution
    # will be needed.

    if acct.coinID == CoinSymbols.decred:
        for net in (nets.mainnet, nets.simnet, nets.testnet):
            if net.Name == acct.netID:
                acct.net = net
                return
        raise Exception("unrecognized network name %s" % acct.netID)
    raise Exception("unrecognized coin type %i" % acct.coinID)

class KeyLengthException(Exception):
    """
    A KeyLengthException indicates a hash input that is of an unexpected length.
    """
    pass

def newMaster(seed, network):
    """
    newMaster creates a new crypto.ExtendedKey.
    Implementation based on dcrd hdkeychain newMaster.
    The ExtendedKey created and any children created through its interface is 
    specific to the network provided. The extended key returned from newMaster
    can be used to generate coin-type and account keys in accordance with 
    BIP-0032 and BIP-0044.

    Args:
        seed (bytes-like): A random seed from which the extended key is made.
        network (obj): an object with BIP32 hierarchical deterministic extended 
            key magics as attributes `HDPrivateKeyID` and `HDPublicKeyID`.

    """
    seedLen = len(seed)
    assert seedLen >= DCR.MinSeedBytes and seedLen <= DCR.MaxSeedBytes

    # First take the HMAC-SHA512 of the master key and the seed data:
    # SHA512 hash is 64 bytes.
    lr = crypto.hmacDigest(MASTER_KEY, seed)

    # Split "I" into two 32-byte sequences Il and Ir where:
    #   Il = master secret key
    #   Ir = master chain code
    lrLen = int(len(lr)/2)
    secretKey = lr[:lrLen]
    chainCode = lr[lrLen:]

    # Ensure the key in usable.
    secretInt = int.from_bytes(secretKey, byteorder='big')
    if secretInt > MAX_SECRET_INT or secretInt <= 0:
        raise KeyLengthException("generated key was outside acceptable range")

    parentFp = bytes.fromhex("00 00 00 00")

    return crypto.ExtendedKey(
        privVer = network.HDPrivateKeyID,
        pubVer = network.HDPublicKeyID,
        key = secretKey,
        pubKey = "",
        chainCode = chainCode,
        parentFP = parentFp,
        depth = 0,
        childNum = 0,
        isPrivate = True,
    )

def coinTypes(params):
    """
    coinTypes returns the legacy and SLIP0044 coin types for the chain
    parameters.  At the moment, the parameters have not been upgraded for the new
    coin types.
    """
    return params.LegacyCoinType, params.SLIP0044CoinType

def checkBranchKeys(acctKey):
    """
    Try to raise an exception.
    checkBranchKeys ensures deriving the extended keys for the internal and
    external branches given an account key does not result in an invalid child
    error which means the chosen seed is not usable.  This conforms to the
    hierarchy described by BIP0044 so long as the account key is already derived
    accordingly.
    
    In particular this is the hierarchical deterministic extended key path:
      m/44'/<coin type>'/<account>'/<branch>
    
    The branch is 0 for external addresses and 1 for internal addresses.
    """
    # Derive the external branch as the first child of the account key.
    acctKey.child(EXTERNAL_BRANCH)

    # Derive the interal branch as the second child of the account key.
    acctKey.child(INTERNAL_BRANCH)

class Balance(object):
    """
    Information about an account's balance.
    The `total` attribute will contain the sum of the value of all UTXOs known 
    for this wallet. The `available` sum is the same, but without those which
    appear to be from immature coinbase or stakebase transactions.
    """
    def __init__(self, total=0, available=0):
        self.total = total
        self.available = available
    def __tojson__(self):
        return {
            "total": self.total,
            "available": self.available,
        }
    @staticmethod
    def __fromjson__(obj):
        return Balance(
            total = obj["total"],
            available = obj["available"]
        )
    def __repr__(self):
        return (
            "Balance(total=%.8f, available=%.8f)" % 
            (self.total*1e-8, self.available*1e-8)
        )
tinyjson.register(Balance)

UTXO = api.UTXO

class Account(object):
    """
    A BIP0044 account. Keys are stored as encrypted strings. The account is 
    JSON-serializable with the tinyjson module. Unencoded keys will not be 
    serialized. 
    """
    def __init__(self, pubKeyEncrypted, privKeyEncrypted, name, coinID, netID):
        """
        Args:
            pubKeyEncrypted (str): The encrypted public key bytes.
            privKeyEncrypted (str): The encrypted private key bytes.
            name (str): Name for the account.
            coinID (str): The lowercase symbol of the asset this account is for.
            netID (str): An identifier that can identify the network for an
                asset. Probably a string such as "testnet".
        """
        self.pubKeyEncrypted = pubKeyEncrypted
        self.privKeyEncrypted = privKeyEncrypted
        self.name = name
        self.coinID = coinID
        self.netID = netID
        self.net = None
        setNetwork(self)
        self.lastExternalIndex = -1
        self.lastInternalIndex = -1
        self.externalAddresses = []
        self.internalAddresses = []
        self.cursor = 0
        self.balance = Balance()
        # maps a txid to a MsgTx for a transaction suspected of being in 
        # mempool.
        self.mempool = {}
        # txs maps a base58 encoded address to a list of txid.
        self.txs = {}
        # utxos is a mapping of utxo key ({txid}#{vout}) to a UTXO. 
        self.utxos = {}
        # If the accounts privKey is set with the private extended key
        # the account is considered "open". close'ing the wallet zeros
        # and drops reference to the privKey. 
        self.privKey = None # The private extended key. 
        self.extPub = None # The external branch public extended key.
        self.intPub = None # The internal branch public extended key.
    def __tojson__(self):
        return {
            "pubKeyEncrypted": self.pubKeyEncrypted,
            "privKeyEncrypted": self.privKeyEncrypted,
            "lastExternalIndex": self.lastExternalIndex,
            "lastInternalIndex": self.lastInternalIndex,
            "name": self.name,
            "coinID": self.coinID,
            "netID": self.netID,
            "externalAddresses": self.externalAddresses,
            "internalAddresses": self.internalAddresses,
            "cursor": self.cursor,
            "txs": self.txs,
            "utxos": self.utxos,
            "balance": self.balance,
        }
    @staticmethod
    def __fromjson__(obj):
        acct = Account(
            obj["pubKeyEncrypted"],
            obj["privKeyEncrypted"],
            obj["name"],
            obj["coinID"],
            obj["netID"],
        )
        acct.lastExternalIndex = obj["lastExternalIndex"]
        acct.lastInternalIndex = obj["lastInternalIndex"]
        acct.externalAddresses = obj["externalAddresses"]
        acct.internalAddresses = obj["internalAddresses"]
        acct.cursor = obj["cursor"]
        acct.txs = obj["txs"]
        acct.utxos = obj["utxos"]
        acct.balance = obj["balance"]
        setNetwork(acct)
        return acct
    def addrTxs(self, addr):
        """
        Get the list of known txid for the provided address.

        Args:
            addr (str): Base-58 encoded address.

        Returns:
            list(str): List of transaction IDs. 
        """
        if addr in self.txs:
            return self.txs[addr]
        return []
    def addressUTXOs(self, addr):
        """
        Get the known unspent transaction outputs for an address.

        Args:
            addr (str): Base-58 encoded address.

        Returns:
            list(UTXO): UTXOs for the provided address.
        """
        return [u for u in self.db["utxo"].values() if u.address == addr]
    def utxoscan(self):
        """
        A generator for iterating UTXOs. None of the UTXO set modifying 
        functions (addUTXO, spendUTXO) should be used during iteration.

        Returns:
            generator(UTXO): A UTXO generator that iterates all known UTXOs.
        """
        for utxo in self.utxos.values():
            yield utxo
    def addUTXO(self, utxo):
        """
        Add a UTXO. 

        Args:
            utxo (UTXO): The UTXO to add.
        """
        self.utxos[utxo.key()] = utxo
    def getUTXO(self, txid, vout):
        """
        Get a UTXO by txid and tx output index. 

        Args:
            txid (str): The hex-encoded transaction ID.
            vout (int): The transaction output index.
        """
        uKey =  UTXO.makeKey(txid,  vout)
        return self.utxos[uKey] if uKey in self.utxos else None
    def caresAboutTxid(self, txid):
        """
        Indicates whether the account has any UTXOs with this transaction ID, or
        has this transaction in mempool.

        Args:
            txid (str): The hex-encoded transaction ID.
        """
        return txid in self.mempool or self.hasUTXOwithTXID(txid)
    def hasUTXOwithTXID(self, txid):
        for utxo in self.utxos.values():
            if utxo.txid == txid:
                return True
        return False
    def UTXOsForTXID(self, txid):
        """
        Get any UTXOs with the provided transaction ID.

        Args:
            txid (str): The hex-encoded transaction ID.
        """
        return [utxo for utxo in self.utxoscan() if utxo.txid == txid]
    def spendUTXOs(self, utxos):
        """
        Spend the UTXO.

        Args:
            utxo (UTXO): The UTXO to spend.
        """
        for utxo in utxos:
            self.spendUTXO(utxo)
    def spendUTXO(self, utxo):
        return self.utxos.pop(utxo.key(), None)
    def resolveUTXOs(self, blockchainUTXOs):
        self.utxos = {u.key(): u for u in blockchainUTXOs}
    def spendTxidVout(self, txid, vout):
        """
        Spend the UTXO.

        Args:
            txid (str): The hex-encoded transaction ID.
            vout (int): The transaction output index.
        """
        return self.utxos.pop(UTXO.makeKey(txid, vout), None)
    def addMempoolTx(self, tx):
        """
        Add a Transaction-implementing object to the mempool.

        Args:
            tx (Transaction): An object that implements the Transaction API
                from tinydecred.api.
        """
        self.mempool[tx.txid()] = tx
    def addTxid(self, addr, txid):
        if not addr in self.txs:
            self.txs[addr] = []
        txids = self.txs[addr]
        if txid not in txids:
            txids.append(txid)
    def confirmTx(self, tx, blockHeight):
        """
        Confirm a transaction. Sets height for any unconfirmed UTXOs in the 
        transaction. Removes the transaction from mempool.

        Args:
            tx (Transaction): An object that implements the Transaction API
                from tinydecred.api.
            blockHeight (int): The height of the transactions block.
        """
        txid = tx.txid()
        self.mempool.pop(txid, None)
        for utxo in self.UTXOsForTXID(txid):
            utxo.height = blockHeight
            if tx.looksLikeCoinbase():
                # this is a coinbase transaction, set the maturity height.
                utxo.maturity = utxo.height + self.net.CoinbaseMaturity
            # else:
            #     utxo.maturity = utxo.height + 1 # Not sure about this
    def calcBalance(self, tipHeight):
        """
        Calculate the balance. The height current height must be provided to 
        separate UTXOs which are not mature. 

        Args:
            tipHeight (int): The current best block height. 
        """
        tot = 0
        avail = 0
        for utxo in self.utxoscan():
            tot += utxo.satoshis
            if not utxo.isSpendable(tipHeight):
                continue
            avail += utxo.satoshis
        self.balance.total = tot
        self.balance.available = avail
        return self.balance
    def generateNextPaymentAddress(self):
        """
        Generate a new address and add it to the list of external addresses.
        Does not move the cursor. 

        Returns:
            addr (str): Base-58 encoded address.
        """
        if len(self.externalAddresses) != self.lastExternalIndex + 1:
            raise Exception("index-address length mismatch")
        idx = self.lastExternalIndex + 1
        try:
            addr = self.extPub.deriveChildAddress(idx, self.net)
        except crypto.ParameterRangeError:
            log.warning("crazy address generated")
            addr = CrazyAddress
        self.externalAddresses.append(addr)
        self.lastExternalIndex = idx
        return addr
    def getNextPaymentAddress(self):
        """
        Get the next address after the cursor and move the cursor.

        Returns:
            addr (str): Base-58 encoded address.
        """
        self.cursor += 1
        while self.cursor >= len(self.externalAddresses):
            self.generateNextPaymentAddress()
        return self.externalAddresses[self.cursor]
    def generateGapAddresses(self, gap):
        """
        Generate addresses up to gap addresses after the cursor. Do not move the
        cursor. 
        """
        if self.extPub is None:
            log.warning("attempting to generate gap addresses on a closed account")
        highest = 0
        for addr in self.txs:
            try:
                highest = max(highest, self.externalAddresses.index(addr))
            except ValueError: # Not found
                continue
        tip = highest + gap
        while len(self.externalAddresses) < tip:
            self.generateNextPaymentAddress()
    def getChangeAddress(self):
        """
        Return a new change address.

        Returns:
            addr (str): Base-58 encoded address.
        """
        if len(self.internalAddresses) != self.lastInternalIndex + 1:
            raise Exception("index-address length mismatch while generating change address")
        idx = self.lastInternalIndex + 1
        try:
            addr = self.intPub.deriveChildAddress(idx, self.net)
        except crypto.ParameterRangeError:
            log.warning("crazy address generated")
            addr = CrazyAddress
        self.internalAddresses.append(addr)
        self.lastInternalIndex = idx
        return addr
    def allAddresses(self):
        """
        Get the list of all known addresses for this account.

        Returns:
            list(str): A list of base-58 encoded addresses. 
        """
        return self.internalAddresses + self.externalAddresses
    def addressesOfInterest(self):
        """
        Get the list of all known addresses for this account.

        Returns:
            list(str): A list of base-58 encoded addresses. 
        """
        a = set()
        for utxo in self.utxoscan():
            a.add(utxo.address)
        ext = self.externalAddresses
        for i in range(max(self.cursor - 10, 0), self.cursor+1):
            a.add(ext[i])
        return a
    def paymentAddress(self):
        """
        Get the external address at the cursor. The cursor is not moved. 

        Returns:
            addr (str): Base-58 encoded address.
        """
        return self.externalAddresses[self.cursor]
    def privateExtendedKey(self, pw):
        """
        Decode the private extended key using the provided SecretKey.

        Args:
            net (obj): Network parameters.
            pw (SecretKey): The secret key.
        """
        return crypto.decodeExtendedKey(self.net, pw, self.privKeyEncrypted)
    def publicExtendedKey(self, pw):
        """
        Decode the public extended key using the provided SecretKey.

        Args:
            net (obj): Network parameters.
            pw (SecretKey): The secret key.
        """
        return crypto.decodeExtendedKey(self.net, pw, self.pubKeyEncrypted)
    def open(self, pw):
        """
        Open the account. While the account is open, the private and public keys
        are stored at least in memory. No precautions are taken to prevent the
        the keys from getting into swap memory, but the ByteArray keys are
        wrappers for mutable Python bytearrays and can be zeroed on close. 

        Args:
            net (obj): Network parameters.
            pw (byte-like): The user supplied password for this account. 
        """
        self.privKey = self.privateExtendedKey(pw)
        pubX = self.privKey.neuter()
        self.extPub = pubX.child(EXTERNAL_BRANCH)
        self.intPub = pubX.child(INTERNAL_BRANCH)
    def close(self):
        """
        Close the account. Zero the keys.
        """
        if self.privKey:
            self.privKey.key.zero()
            self.privKey.pubKey.zero()
            self.extPub.key.zero()
            self.extPub.pubKey.zero()            
            self.intPub.key.zero()
            self.intPub.pubKey.zero()
        self.privKey = None
        self.extPub = None
        self.intPub = None
    def branchAndIndex(self, addr):
        """
        Find the branch and index of the address.

        Args:
            addr (str): Base-58 encoded address.
        """
        branch, idx = None, None
        if addr in self.externalAddresses:
            branch = EXTERNAL_BRANCH
            idx = self.externalAddresses.index(addr)
        elif addr in self.internalAddresses:
            branch = INTERNAL_BRANCH
            idx = self.internalAddresses.index(addr)
        return branch, idx
    def getPrivKeyForAddress(self, addr):
        """
        Get the private key for the address.

        Args:
            addr (str): Base-58 encoded address.
        """
        branch, idx = self.branchAndIndex(addr)
        if branch is None:
            raise Exception("unknown address")

        branchKey = self.privKey.child(branch)
        privKey = branchKey.child(idx)
        return crypto.privKeyFromBytes(privKey.key)

tinyjson.register(Account)

class AccountManager(object):
    """
    The AccountManager provides generation, organization, and other management 
    of Accounts. 
    """
    def __init__(self, cryptoKeyPubEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc, 
        coinTypeLegacyPubEnc, coinTypeLegacyPrivEnc, coinTypeSLIP0044PubEnc, coinTypeSLIP0044PrivEnc, baseAccount,
        privParams, pubParams):
        # The crypto keys are used to decrypt the other keys. 
        self.cryptoKeyPubEnc = cryptoKeyPubEnc
        self.cryptoKeyPrivEnc = cryptoKeyPrivEnc
        self.cryptoKeyScriptEnc = cryptoKeyScriptEnc

        # The coin-type keys are used to generate encrypt a master key that
        # can be used to generate account for any BIP0044 coin.
        self.coinTypeLegacyPubEnc = coinTypeLegacyPubEnc
        self.coinTypeLegacyPrivEnc = coinTypeLegacyPrivEnc
        self.coinTypeSLIP0044PubEnc = coinTypeSLIP0044PubEnc
        self.coinTypeSLIP0044PrivEnc = coinTypeSLIP0044PrivEnc

        self.baseAccount = baseAccount

        # The Scrypt parameters used to encrypt the crypto keys.
        self.privParams = privParams
        self.pubParams = pubParams

        self.watchingOnly = False
        self.accounts = []
    def __tojson__(self):
        return {
            "cryptoKeyPubEnc": self.cryptoKeyPubEnc,
            "cryptoKeyPrivEnc": self.cryptoKeyPrivEnc,
            "cryptoKeyScriptEnc": self.cryptoKeyScriptEnc,
            "coinTypeLegacyPubEnc": self.coinTypeLegacyPubEnc,
            "coinTypeLegacyPrivEnc": self.coinTypeLegacyPrivEnc,
            "coinTypeSLIP0044PubEnc": self.coinTypeSLIP0044PubEnc,
            "coinTypeSLIP0044PrivEnc": self.coinTypeSLIP0044PrivEnc,
            "baseAccount": self.baseAccount,
            "privParams": self.privParams,
            "pubParams": self.pubParams,
            "watchingOnly": self.watchingOnly,
            "accounts": self.accounts,
        }
    @staticmethod
    def __fromjson__(obj):
        manager = AccountManager(
            cryptoKeyPubEnc = obj["cryptoKeyPubEnc"],
            cryptoKeyPrivEnc = obj["cryptoKeyPrivEnc"],
            cryptoKeyScriptEnc = obj["cryptoKeyScriptEnc"],
            coinTypeLegacyPubEnc = obj["coinTypeLegacyPubEnc"],
            coinTypeLegacyPrivEnc = obj["coinTypeLegacyPrivEnc"],
            coinTypeSLIP0044PubEnc = obj["coinTypeSLIP0044PubEnc"],
            coinTypeSLIP0044PrivEnc = obj["coinTypeSLIP0044PrivEnc"],
            baseAccount = obj["baseAccount"],
            privParams = obj["privParams"],
            pubParams = obj["pubParams"],
        )
        manager.watchingOnly = obj["watchingOnly"]
        manager.accounts = obj["accounts"]
        return manager
    def addAccount(self, account):
        """
        Add the account. No checks are done to ensure the account is correctly
        placed for its index.

        Args:
            account (Account): The account to add. 
        """
        self.accounts.append(account)
    def account(self, idx):
        """
        Get the account at the provided index.

        Args:
            idx (int): The account index. 
        """
        return self.accounts[idx]
    def openAccount(self, acct, pw):
        """
        Open an account. 

        Args:
            acct (int): The acccount index, which is its position in the accounts
                list. 
            net (obj): Network parameters.
            pw (byte-like): An UTF-8-encoded user-supplied password for the
                account.

        Returns:
            Account: The open account. 
        """
        # A string at this point is considered to be ascii, not hex. 
        if isinstance(pw, str):
            pw = pw.encode()
        # Generate the master key, which is used to decrypt the crypto keys.
        userSecret = crypto.SecretKey.rekey(pw, self.privParams)
        # Decrypt the crypto keys.
        cryptKeyPriv = ByteArray(userSecret.decrypt(self.cryptoKeyPrivEnc.bytes()))
        # Retreive and open the account.
        account = self.accounts[acct]
        account.open(cryptKeyPriv)
        return account
    def acctPrivateKey(self, acct, net, pw):
        userSecret = crypto.SecretKey.rekey(pw, self.privParams)
        cryptKeyPriv = ByteArray(userSecret.decrypt(self.cryptoKeyPrivEnc.bytes()))
        account = self.accounts[acct]
        return account.privateExtendedKey(cryptKeyPriv)
    def acctPublicKey(self, acct, net, pw):
        userSecret = crypto.SecretKey.rekey(pw, self.pubParams)
        cryptKeyPub = ByteArray(userSecret.decrypt(self.cryptoKeyPubEnc.bytes()))
        account = self.accounts[acct]
        return account.publicExtendedKey(cryptKeyPub)

tinyjson.register(AccountManager)

def createNewAccountManager(seed, pubPassphrase, privPassphrase, chainParams):
    """
    Create a new account manager and a set of BIP0044 keys for creating 
    accounts. The zeroth account is created for the provided network parameters. 

    Args:
        pubPassphrase (byte-like): A user-supplied password to protect the 
            public keys. The public keys can always be generated from the 
            private keys, but it may be convenient to perform some actions,
            such as address generation, without decrypting the private keys. 
        privPassphrase (byte-like): A user-supplied password to protect the 
            private the account private keys. 
        chainParams (obj): Network parameters. 
    """

    # Ensure the private passphrase is not empty.
    if len(privPassphrase) == 0:
        raise Exception("createAddressManager: private passphrase cannot be empty")

    # Derive the master extended key from the seed.
    root = newMaster(seed, chainParams)

    # Derive the cointype keys according to BIP0044.
    legacyCoinType, slip0044CoinType = coinTypes(chainParams)

    coinTypeLegacyKeyPriv = root.deriveCoinTypeKey(legacyCoinType)

    coinTypeSLIP0044KeyPriv = root.deriveCoinTypeKey(slip0044CoinType)

    # Derive the account key for the first account according to BIP0044.
    acctKeyLegacyPriv = coinTypeLegacyKeyPriv.deriveAccountKey(0)
    acctKeySLIP0044Priv = coinTypeSLIP0044KeyPriv.deriveAccountKey(0)

    # Ensure the branch keys can be derived for the provided seed according
    # to BIP0044.
    checkBranchKeys(acctKeyLegacyPriv)
    checkBranchKeys(acctKeySLIP0044Priv)

    # The address manager needs the public extended key for the account.
    acctKeyLegacyPub = acctKeyLegacyPriv.neuter()

    acctKeySLIP0044Pub = acctKeySLIP0044Priv.neuter()

    # Generate new master keys.  These master keys are used to protect the
    # crypto keys that will be generated next.
    masterKeyPub = crypto.SecretKey(pubPassphrase)

    masterKeyPriv = crypto.SecretKey(privPassphrase)

    # Generate new crypto public, private, and script keys.  These keys are
    # used to protect the actual public and private data such as addresses,
    # extended keys, and scripts.
    cryptoKeyPub = ByteArray(generateSeed(crypto.KEY_SIZE))

    cryptoKeyPriv = ByteArray(generateSeed(crypto.KEY_SIZE))

    cryptoKeyScript = ByteArray(generateSeed(crypto.KEY_SIZE))

#   // Encrypt the crypto keys with the associated master keys.
    cryptoKeyPubEnc = masterKeyPub.encrypt(cryptoKeyPub.b)

    cryptoKeyPrivEnc = masterKeyPriv.encrypt(cryptoKeyPriv.b)

    cryptoKeyScriptEnc = masterKeyPriv.encrypt(cryptoKeyScript.b)

    # Encrypt the legacy cointype keys with the associated crypto keys.
    coinTypeLegacyKeyPub = coinTypeLegacyKeyPriv.neuter()

    ctpes = coinTypeLegacyKeyPub.string()
    coinTypeLegacyPubEnc = cryptoKeyPub.encrypt(ctpes.encode())

    ctpes = coinTypeLegacyKeyPriv.string()
    coinTypeLegacyPrivEnc = cryptoKeyPriv.encrypt(ctpes.encode())

    # Encrypt the SLIP0044 cointype keys with the associated crypto keys.
    coinTypeSLIP0044KeyPub = coinTypeSLIP0044KeyPriv.neuter()
    ctpes = coinTypeSLIP0044KeyPub.string()
    coinTypeSLIP0044PubEnc = cryptoKeyPub.encrypt(ctpes.encode())

    ctpes = coinTypeSLIP0044KeyPriv.string()
    coinTypeSLIP0044PrivEnc = cryptoKeyPriv.encrypt(ctpes.encode())

    # Encrypt the default account keys with the associated crypto keys.
    apes = acctKeyLegacyPub.string()
    acctPubLegacyEnc = cryptoKeyPub.encrypt(apes.encode())

    apes = acctKeyLegacyPriv.string()
    acctPrivLegacyEnc = cryptoKeyPriv.encrypt(apes.encode())

    apes = acctKeySLIP0044Pub.string()
    acctPubSLIP0044Enc = cryptoKeyPub.encrypt(apes.encode())

    apes = acctKeySLIP0044Priv.string()
    acctPrivSLIP0044Enc = cryptoKeyPriv.encrypt(apes.encode())

    # Save the information for the default account to the database.  This
    # account is derived from the legacy coin type.
    baseAccount = Account(acctPubLegacyEnc, acctPrivLegacyEnc, 
        DEFAULT_ACCOUNT_NAME, CoinSymbols.decred, chainParams.Name)

    # Save the account row for the 0th account derived from the coin type
    # 42 key.
    zerothAccount = Account(acctPubSLIP0044Enc, acctPrivSLIP0044Enc, 
        DEFAULT_ACCOUNT_NAME, CoinSymbols.decred, chainParams.Name)
    # Open the account
    zerothAccount.open(cryptoKeyPriv)
    # Create the first payment address
    zerothAccount.generateNextPaymentAddress()
    # Close the account to zero the key
    zerothAccount.close()


    # ByteArray is mutable, so erase the keys.
    cryptoKeyPriv.zero()
    cryptoKeyScript.zero()

    log.debug("coinTypeLegacyKeyPriv: %s\n" % coinTypeLegacyKeyPriv.string())
    log.debug("coinTypeSLIP0044KeyPriv: %s\n" % coinTypeSLIP0044KeyPriv.string())
    log.debug("acctKeyLegacyPriv: %s\n" % acctKeyLegacyPriv.string())
    log.debug("acctKeySLIP0044Priv: %s\n" % acctKeySLIP0044Priv.string())
    log.debug("acctKeyLegacyPub: %s\n" % acctKeyLegacyPub.string())
    log.debug("acctKeySLIP0044Pub: %s\n" % acctKeySLIP0044Pub.string())
    log.debug("cryptoKeyPubEnc: %s\n" % cryptoKeyPubEnc.hex())
    log.debug("cryptoKeyPrivEnc: %s\n" % cryptoKeyPrivEnc.hex())
    log.debug("cryptoKeyScriptEnc: %s\n" % cryptoKeyScriptEnc.hex())
    log.debug("coinTypeLegacyKeyPub: %s\n" % coinTypeLegacyKeyPub.string())
    log.debug("coinTypeLegacyPubEnc: %s\n" % coinTypeLegacyPubEnc.hex())
    log.debug("coinTypeLegacyPrivEnc: %s\n" % coinTypeLegacyPrivEnc.hex())
    log.debug("coinTypeSLIP0044KeyPub: %s\n" % coinTypeSLIP0044KeyPub.string())
    log.debug("coinTypeSLIP0044PubEnc: %s\n" % coinTypeSLIP0044PubEnc.hex())
    log.debug("coinTypeSLIP0044PrivEnc: %s\n" % coinTypeSLIP0044PrivEnc.hex())
    log.debug("acctPubLegacyEnc: %s\n" % acctPubLegacyEnc.hex())
    log.debug("acctPrivLegacyEnc: %s\n" % acctPrivLegacyEnc.hex())
    log.debug("acctPubSLIP0044Enc: %s\n" % acctPubSLIP0044Enc.hex())
    log.debug("acctPrivSLIP0044Enc: %s\n" % acctPrivSLIP0044Enc.hex())

    manager = AccountManager(
        cryptoKeyPubEnc = cryptoKeyPubEnc,
        cryptoKeyPrivEnc = cryptoKeyPrivEnc,
        cryptoKeyScriptEnc = cryptoKeyScriptEnc,
        coinTypeLegacyPubEnc = coinTypeLegacyPubEnc,
        coinTypeLegacyPrivEnc = coinTypeLegacyPrivEnc,
        coinTypeSLIP0044PubEnc = coinTypeSLIP0044PubEnc,
        coinTypeSLIP0044PrivEnc = coinTypeSLIP0044PrivEnc,
        baseAccount = baseAccount,
        privParams = masterKeyPriv.params(),
        pubParams = masterKeyPub.params(),
    )
    manager.addAccount(zerothAccount)
    return manager

testSeed = ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b

def addressForPubkeyBytes(b, net):
    return crypto.newAddressPubKeyHash(crypto.hash160(b), net, crypto.STEcdsaSecp256k1).string()



class TestAccounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.prepareLogger("TestTinyCrypto")
        # log.setLevel(0)
    def test_child_neuter(self):
        extKey = newMaster(testSeed, nets.mainnet)
        extKey.child(0)
        pub = extKey.neuter()
        self.assertEqual(pub.string(), "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbRqbfTCJ9BUnWPCkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk")
    def test_accounts(self):
        pw = "abc".encode()
        am = createNewAccountManager(testSeed, bytearray(0), pw, nets.mainnet)
        rekey = am.acctPrivateKey(0, nets.mainnet, pw)
        pubFromPriv = rekey.neuter()
        addr1 = pubFromPriv.deriveChildAddress(5, nets.mainnet)
        pubKey = am.acctPublicKey(0, nets.mainnet, "")
        addr2 = pubKey.deriveChildAddress(5, nets.mainnet)
        self.assertEqual(addr1, addr2)
        acct = am.openAccount(0, pw)
        for n in range(20):
            acct.getNextPaymentAddress()
        v = 5
        satoshis = v*1e8
        txid = "abcdefghijkl"
        vout = 2
        from tinydecred.pydecred import dcrdata
        utxo = dcrdata.UTXO(
            address = None,
            txid = txid,
            vout = vout,
            scriptPubKey = ByteArray(0),
            amount = v,
            satoshis = satoshis,
            maturity = 1,
        )
        utxocount = lambda: len(list(acct.utxoscan()))
        acct.addUTXO(utxo)
        self.assertEqual(utxocount(), 1)
        self.assertEqual(acct.calcBalance(1).total, satoshis)
        self.assertEqual(acct.calcBalance(1).available, satoshis)
        self.assertEqual(acct.calcBalance(0).available, 0)
        self.assertIsNot(acct.getUTXO(txid, vout), None)
        self.assertIs(acct.getUTXO("", -1), None)
        self.assertTrue(acct.caresAboutTxid(txid))
        utxos = acct.UTXOsForTXID(txid)
        self.assertEqual(len(utxos), 1)
        acct.spendUTXOs(utxos)
        self.assertEqual(utxocount(), 0)
        acct.addUTXO(utxo)
        self.assertEqual(utxocount(), 1)
        acct.spendUTXO(utxo)
        self.assertEqual(utxocount(), 0)
    def test_newmaster(self):
        kpriv = newMaster(testSeed, nets.mainnet)
        # --extKey: f2418d00085be520c6449ddb94b25fe28a1944b5604193bd65f299168796f862
        # --kpub: 0317a47499fb2ef0ff8dc6133f577cd44a5f3e53d2835ae15359dbe80c41f70c9b
        # --kpub_branch0: 02dfed559fddafdb8f0041cdd25c4f9576f71b0e504ce61837421c8713f74fb33c
        # --kpub_branch0_child1: 03745417792d529c66980afe36f364bee6f85a967bae117bc4d316b77e7325f50c
        # --kpriv_branch0: 6469a8eb3ed6611cc9ee4019d44ec545f3174f756cc41f9867500efdda742dd9
        # --kpriv_branch0_child1: fb8efe52b3e4f31bc12916cbcbfc0e84ef5ebfbceb7197b8103e8009c3a74328

        self.assertEqual(kpriv.key.hex(), "f2418d00085be520c6449ddb94b25fe28a1944b5604193bd65f299168796f862")
        kpub = kpriv.neuter()
        self.assertEqual(kpub.key.hex(), "0317a47499fb2ef0ff8dc6133f577cd44a5f3e53d2835ae15359dbe80c41f70c9b")
        kpub_branch0 = kpub.child(0)
        self.assertEqual(kpub_branch0.key.hex(), "02dfed559fddafdb8f0041cdd25c4f9576f71b0e504ce61837421c8713f74fb33c")
        kpub_branch0_child1 = kpub_branch0.child(1)
        self.assertEqual(kpub_branch0_child1.key.hex(), "03745417792d529c66980afe36f364bee6f85a967bae117bc4d316b77e7325f50c")
        kpriv_branch0 = kpriv.child(0)
        self.assertEqual(kpriv_branch0.key.hex(), "6469a8eb3ed6611cc9ee4019d44ec545f3174f756cc41f9867500efdda742dd9")
        kpriv_branch0_child1 = kpriv_branch0.child(1)
        self.assertEqual(kpriv_branch0_child1.key.hex(), "fb8efe52b3e4f31bc12916cbcbfc0e84ef5ebfbceb7197b8103e8009c3a74328")
        kpriv01_neutered = kpriv_branch0_child1.neuter()
        self.assertEqual(kpriv01_neutered.key.hex(), kpub_branch0_child1.key.hex())
    def test_change_addresses(self):
        pw = "abc".encode()
        acctManager = createNewAccountManager(testSeed, bytearray(0), pw, nets.mainnet)
        # acct = acctManager.account(0)
        acct = acctManager.openAccount(0, pw)
        for i in range(10):
            acct.getChangeAddress()

if __name__ == "__main__":
    pass