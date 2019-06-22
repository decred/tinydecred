"""
Copyright (c) 2019, The Decred developers
Copyright (c) 2018-2019, Brian Stafford
See LICENSE for details

tinycrypto package
    Mostly account handling, interaction with this package's functions will 
    mostly be through the AccountManager.
    The tinycrypto package relies heavily on the lower-level crypto modules.


Much inspiration from https://github.com/decred/dcrd/blob/master/dcrec/secp256k1
"""
import unittest
import hashlib
import hmac
from tinydecred.pydecred import dcrjson as json, mainnet, simnet, helpers
from tinydecred.pydecred import constants as C
from tinydecred.crypto import crypto
from tinydecred.crypto import txscript
from tinydecred.crypto.rando import generateSeed
from tinydecred.crypto.bytearray import ByteArray


EXTERNAL_BRANCH = 0
INTERNAL_BRANCH = 1
MASTER_KEY = b"Bitcoin seed"
MAX_SECRET_INT = 115792089237316195423570985008687907852837564279074904382605163141518161494337
SALT_SIZE = 32
DEFAULT_ACCOUNT_NAME = "default"

CrazyAddress = "CRAZYADDRESS"

log = helpers.getLogger("TCRYP") #, logLvl=0)

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

    :param seed bytes-like: A random seed from which the extended key is made.
    :param network: an object with BIP32 hierarchical deterministic extended key
        magics as attributes `HDPrivateKeyID` and `HDPublicKeyID`.

    """
    seedLen = len(seed)
    assert seedLen >= C.MinSeedBytes and seedLen <= C.MaxSeedBytes

    # First take the HMAC-SHA512 of the master key and the seed data:
    lr = hmac.digest(MASTER_KEY, msg=seed, digest=hashlib.sha512)

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

    return crypto.ExtendedKey( #privVer, pubVer, key, chainCode, parentFP, depth, childNum, isPrivate)
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

class Balance:
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
json.register(Balance)

class UTXO:
    def __init__(self, address, txid, vout, ts=None, scriptPubKey=None, 
                 height=-1, amount=0, satoshis=0, maturity=None):
        self.address = address
        self.txid = txid
        self.vout = vout
        self.ts = ts
        self.scriptPubKey = scriptPubKey
        self.height = height
        self.amount = amount
        self.satoshis = satoshis
        self.maturity = None
    def __tojson__(self):
        return {
            "address": self.address,
            "txid": self.txid,
            "vout": self.vout,
            "ts": self.ts,
            "scriptPubKey": self.scriptPubKey,
            "height": self.height,
            "amount": self.amount,
            "satoshis": self.satoshis,
            "maturity": self.maturity,
        }
    @staticmethod
    def __fromjson__(obj):
        return UTXO.parse(obj)
    @staticmethod
    def parse(obj):
        return UTXO(
            address = obj["address"],
            txid = obj["txid"],
            vout = obj["vout"],
            ts = obj["ts"] if "ts" in obj else None,
            scriptPubKey = obj["scriptPubKey"] if "scriptPubKey" in obj else None,
            height = obj["height"] if "height" in obj else -1,
            amount = obj["amount"] if "amount" in obj else 0,
            satoshis = obj["satoshis"] if "satoshis" in obj else 0,
            maturity = obj["maturity"] if "maturity" else None,
        )
    def isConfirmed(self):
        return self.height > -1
    def key(self):
        return UTXO.makeKey(self.txid, self.vout)
    @staticmethod
    def makeKey(txid, vout):
        return txid + "#" + str(vout)

json.register(UTXO)

class Account:
    def __init__(self, pubKeyEncrypted, privKeyEncrypted, name):
        self.pubKeyEncrypted = pubKeyEncrypted
        self.privKeyEncrypted = privKeyEncrypted
        self.name = name
        self.net = None
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
        self.privKey = None
        self.extPub = None
        self.intPub = None
        self.generateSalt()
    def __tojson__(self):
        return {
            "pubKeyEncrypted": self.pubKeyEncrypted,
            "privKeyEncrypted": self.privKeyEncrypted,
            "lastExternalIndex": self.lastExternalIndex,
            "lastInternalIndex": self.lastInternalIndex,
            "name": self.name,
            "externalAddresses": self.externalAddresses,
            "internalAddresses": self.internalAddresses,
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
        )
        acct.lastExternalIndex = obj["lastExternalIndex"]
        acct.lastInternalIndex = obj["lastInternalIndex"]
        acct.name = obj["name"]
        acct.externalAddresses = obj["externalAddresses"]
        acct.internalAddresses = obj["internalAddresses"]
        acct.db = obj["db"]
        acct.txs = obj["txs"]
        acct.utxos = obj["utxos"]
        acct.balance = obj["balance"]
        return acct
    def addrTxs(self, addr):
        if addr in self.txs:
            return self.txs[addr]
        return []
    def addressUTXOs(self, addr):
        return [u for u in self.db["utxo"].values() if u.address == addr]
    def utxoscan(self):
        for utxo in self.utxos.values():
            yield utxo
    def addUTXO(self, utxo):
        self.unconfirmedUTXOs[utxo.key()] = utxo
    def getUTXO(self, txid, vout):
        uKey =  UTXO.makeKey(txid,  vout)
        return self.utxos[uKey] if uKey in self.utxos else None
    def addrHasUTXOs(self, addr):
        for utxo in self.utxos:
            if utxo.address == addr:
                return True
        return False
    def addrHasTxs(self, addr):
        return addr in self.txs and len(self.txs[addr]) > 0
    def caresAboutTxid(self, txid):
        return txid in self.mempool or self.hasUTXOwithTXID(txid)
    def hasUTXOwithTXID(self, txid):
        for utxo in self.utxos.value():
            if utxo.txid == txid:
                return True
        return False
    def UTXOsForTXID(self, txid):
        return [utxo for utxo in self.unconfirmedUTXOs.values() if utxo.txid == txid]
    # def checkCursor(self, addr):
    #     branch, idx = self.getBranchIdx(addr)
    #     if branch is None or branch != EXTERNAL_BRANCH:
    #         return
    #     if idx > self.cursor:
    #         # consider generating new addresses here
    #         self.cursor = idx + 1
    def spendUTXOs(self, utxos):
        for utxo in utxos:
            self.utxos(utxo["address"]).pop(utxo.key, None)
    def spendTxidVout(self, txid, vout):
        return self.utxos.pop(UTXO.makeKey(txid, vout), None)
    def addMempoolTx(self, tx):
        self.mempool[tx.txid()] = tx
    def confirmTx(self, tx, blockHeight):
        txid = tx.txid()
        self.mempool.pop(txid, None)
        for utxo in self.UTXOsForTXID(txid):
            utxo.height = blockHeight
            if tx.looksLikeCoinbase():
                # this is a coinbase transaction, set the maturity height.
                utxo.maturity = utxo.height + self.net.CoinbaseMaturity
    def addTx(self, addr, txid):
        if addr not in self.txs:
            self.txs[addr] = []
        txids = self.txs[addr]
        if txid not in txids:
            txids.append(txid)
    def calcBalance(self, tipHeight):
        tot = 0
        avail = 0
        for utxo in self.utxos:
            tot += utxo.satoshis
            if utxo.maturity and utxo.maturity > tipHeight:
                continue
            if not utxo.isConfirmed():
                continue
            avail += utxo.satoshis
        self.balance.total = tot
        self.balance.avail = avail
        return self.balance
    def generateNextPaymentAddress(self):
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
        self.cursor += 1
        if self.cursor > len(self.externalAddresses):
            self.cursor = len(self.externalAddresses) - 1
        return self.externalAddresses(self.cursor)
    def generateGapAddresses(self, gap):
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
        return self.internalAddresses + self.externalAddressess
    def addressesOfInterest(self):
        a = set()
        for utxo in self.utxoscan():
            a.add(utxo.address)
        ext = self.externalAddresses
        for i in range(max(self.cursor - 10, 0), self.cursor+1):
            a.add(ext[i])
        return a
    def paymentAddress(self):
        return self.externalAddresses[self.cursor]
    def generateSalt(self):
        self.privPassphraseSalt = ByteArray(generateSeed(SALT_SIZE))
    def privateExtendedKey(self, net, pw):
        return crypto.decodeExtendedKey(net, pw, self.privKeyEncrypted)
    def publicExtendedKey(self, net, pw):
        return crypto.decodeExtendedKey(net, pw, self.pubKeyEncrypted)
    def open(self, net, pw):
        self.net = net
        self.privKey = self.privateExtendedKey(net, pw)
        pubX = self.privKey.neuter()
        self.extPub = pubX.child(EXTERNAL_BRANCH)
        self.intPub = pubX.child(INTERNAL_BRANCH)
    def close(self):
        if self.privKey:
            self.privKey.key.zero()
            self.privKey.pubKey.zero()
        self.privKey = None
    def branchAndIndex(self, addr):
        branch, idx = None, None
        if addr in self.externalAddresses:
            branch = EXTERNAL_BRANCH
            idx = self.externalAddresses.index(addr)
        elif addr in self.internalAddresses:
            branch = INTERNAL_BRANCH
            idx = self.internalAddresses.index(addr)
        return branch, idx
    def getPrivKeyForAddress(self, addr):
        branch, idx = self.branchAndIndex(addr)
        if branch is None:
            raise Exception("unknown address")

        branchKey = self.privKey.child(branch)
        privKey = branchKey.child(idx)
        return crypto.privKeyFromBytes(privKey.key)

json.register(Account)

class AccountManager:
    def __init__(self, cryptoKeyPubEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc, 
        coinTypeLegacyPubEnc, coinTypeLegacyPrivEnc, coinTypeSLIP0044PubEnc, coinTypeSLIP0044PrivEnc, baseAccount,
        privParams, pubParams):
        """
        
        """
        self.cryptoKeyPubEnc = cryptoKeyPubEnc
        self.cryptoKeyPrivEnc = cryptoKeyPrivEnc
        self.cryptoKeyScriptEnc = cryptoKeyScriptEnc
        self.coinTypeLegacyPubEnc = coinTypeLegacyPubEnc
        self.coinTypeLegacyPrivEnc = coinTypeLegacyPrivEnc
        self.coinTypeSLIP0044PubEnc = coinTypeSLIP0044PubEnc
        self.coinTypeSLIP0044PrivEnc = coinTypeSLIP0044PrivEnc
        self.baseAccount = baseAccount
        self.privParams = privParams
        self.pubParams = pubParams

        self.watchingOnly = False
        self.nextInternalIndex = 0
        self.nextExternalIndex = 0
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
            "nextInternalIndex": self.nextInternalIndex,
            "nextExternalIndex": self.nextExternalIndex,
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
        manager.nextInternalIndex = obj["nextInternalIndex"]
        manager.nextExternalIndex = obj["nextExternalIndex"]
        manager.accounts = obj["accounts"]
        return manager
    def addAccount(self, account):
        self.accounts.append(account)
    def account(self, idx):
        return self.accounts[idx]
    def openAccount(self, idx, net, pw):
        userSecret = crypto.SecretKey.rekey(pw, self.privParams)
        cryptKeyPriv = ByteArray(userSecret.decrypt(self.cryptoKeyPrivEnc.bytes()))
        account = self.accounts[idx]
        account.open(net, cryptKeyPriv)
        return account
    def acctPrivateKey(self, acct, net, pw):
        userSecret = crypto.SecretKey.rekey(pw, self.privParams)
        cryptKeyPriv = ByteArray(userSecret.decrypt(self.cryptoKeyPrivEnc.bytes()))
        account = self.accounts[acct]
        return account.privateExtendedKey(net, cryptKeyPriv)
    def acctPublicKey(self, acct, net, pw):
        userSecret = crypto.SecretKey.rekey(pw, self.pubParams)
        cryptKeyPub = ByteArray(userSecret.decrypt(self.cryptoKeyPubEnc.bytes()))
        account = self.accounts[acct]
        return account.publicExtendedKey(net, cryptKeyPub)


json.register(AccountManager)

def createNewAccountManager(seed, pubPassphrase, privPassphrase, chainParams):
    """
    ns walletdb.ReadWriteBucket
    seed, pubPassphrase, privPassphrase []byte
    chainParams *chaincfg.Params
    """
    # # Return an error if the manager has already been created in the given
    # # database namespace.
    # if managerExists(ns) {
    #   return errors.E(errors.Exist, "address manager already exists")
    # }

    # Ensure the private passphrase is not empty.
    if len(privPassphrase) == 0:
        raise Exception("createAddressManager: private passphrase cannot be empty")


#   // Perform the initial bucket creation and database namespace setup.
#   if err := createManagerNS(ns); err != nil {
#       return err
#   }

    # Generate the BIP0044 HD key structure to ensure the provided seed
    # can generate the required structure with no issues.

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
    coinTypeLegacyPubEnc = cryptoKeyPub.encrypt(ctpes.encode("ascii"))

    ctpes = coinTypeLegacyKeyPriv.string()
    coinTypeLegacyPrivEnc = cryptoKeyPriv.encrypt(ctpes.encode("ascii"))

    # Encrypt the SLIP0044 cointype keys with the associated crypto keys.
    coinTypeSLIP0044KeyPub = coinTypeSLIP0044KeyPriv.neuter()
    ctpes = coinTypeSLIP0044KeyPub.string()
    coinTypeSLIP0044PubEnc = cryptoKeyPub.encrypt(ctpes.encode("ascii"))

    ctpes = coinTypeSLIP0044KeyPriv.string()
    coinTypeSLIP0044PrivEnc = cryptoKeyPriv.encrypt(ctpes.encode("ascii"))

    # Encrypt the default account keys with the associated crypto keys.
    apes = acctKeyLegacyPub.string()
    acctPubLegacyEnc = cryptoKeyPub.encrypt(apes.encode("ascii"))

    apes = acctKeyLegacyPriv.string()
    acctPrivLegacyEnc = cryptoKeyPriv.encrypt(apes.encode("ascii"))

    apes = acctKeySLIP0044Pub.string()
    acctPubSLIP0044Enc = cryptoKeyPub.encrypt(apes.encode("ascii"))

    apes = acctKeySLIP0044Priv.string()
    acctPrivSLIP0044Enc = cryptoKeyPriv.encrypt(apes.encode("ascii"))


    branch0Priv = acctKeySLIP0044Priv.child(0)
    branch0child1Priv = branch0Priv.child(1)

    branch0Pub = acctKeySLIP0044Pub.child(0)
    branch0child1Pub = branch0Pub.child(1)

    pubFromPriv = branch0child1Priv.privateKey().pub
    pubFromPub = branch0child1Pub.publicKey()

    print("-- %s == %s?" % (pubFromPriv.x, pubFromPub.x))
    print("-- %s == %s?" % (pubFromPriv.y, pubFromPub.y))

    # Save the information for the default account to the database.  This
    # account is derived from the legacy coin type.
    baseAccount = Account(acctPubLegacyEnc, acctPrivLegacyEnc, DEFAULT_ACCOUNT_NAME)

    # Save the account row for the 0th account derived from the coin type
    # 42 key.
    zerothAccount = Account(acctPubSLIP0044Enc, acctPrivSLIP0044Enc, DEFAULT_ACCOUNT_NAME)
    # Open the account
    zerothAccount.open(chainParams, cryptoKeyPriv)
    # Create the first payment address
    zerothAccount.generateNextPaymentAddress()
    # Close the account to zero the key
    zerothAccount.close()


    # ByteArray is mutable, so erase the keys.
    cryptoKeyPriv.zero()
    cryptoKeyScript.zero()

    log.debug("--coinTypeLegacyKeyPriv: %s\n" % coinTypeLegacyKeyPriv.string())
    log.debug("--coinTypeSLIP0044KeyPriv: %s\n" % coinTypeSLIP0044KeyPriv.string())
    log.debug("--acctKeyLegacyPriv: %s\n" % acctKeyLegacyPriv.string())
    log.debug("--acctKeySLIP0044Priv: %s\n" % acctKeySLIP0044Priv.string())
    log.debug("--acctKeyLegacyPub: %s\n" % acctKeyLegacyPub.string())
    log.debug("--acctKeySLIP0044Pub: %s\n" % acctKeySLIP0044Pub.string())
    log.debug("--cryptoKeyPubEnc: %s\n" % cryptoKeyPubEnc.hex())
    log.debug("--cryptoKeyPrivEnc: %s\n" % cryptoKeyPrivEnc.hex())
    log.debug("--cryptoKeyScriptEnc: %s\n" % cryptoKeyScriptEnc.hex())
    log.debug("--coinTypeLegacyKeyPub: %s\n" % coinTypeLegacyKeyPub.string())
    log.debug("--coinTypeLegacyPubEnc: %s\n" % coinTypeLegacyPubEnc.hex())
    log.debug("--coinTypeLegacyPrivEnc: %s\n" % coinTypeLegacyPrivEnc.hex())
    log.debug("--coinTypeSLIP0044KeyPub: %s\n" % coinTypeSLIP0044KeyPub.string())
    log.debug("--coinTypeSLIP0044PubEnc: %s\n" % coinTypeSLIP0044PubEnc.hex())
    log.debug("--coinTypeSLIP0044PrivEnc: %s\n" % coinTypeSLIP0044PrivEnc.hex())
    log.debug("--acctPubLegacyEnc: %s\n" % acctPubLegacyEnc.hex())
    log.debug("--acctPrivLegacyEnc: %s\n" % acctPrivLegacyEnc.hex())
    log.debug("--acctPubSLIP0044Enc: %s\n" % acctPubSLIP0044Enc.hex())
    log.debug("--acctPrivSLIP0044Enc: %s\n" % acctPrivSLIP0044Enc.hex())

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

testSeed = ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", mainnet)

def addressForPubkeyBytes(b, net):
    return crypto.newAddressPubKeyHash(crypto.hash160(b), net, crypto.STEcdsaSecp256k1).string()

class TestTinyCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.prepareLogger("TestTinyCrypto")
        # log.setLevel(0)
    def test_encode_decode(self):
        extKey = newMaster(generateSeed(), mainnet)
        jsonKey = json.dump(extKey)
        newKey = json.load(jsonKey)

        self.assertEqual(extKey.privVer, newKey.privVer)
        self.assertEqual(extKey.pubVer, newKey.pubVer)
        self.assertEqual(extKey.key, newKey.key)
        self.assertEqual(extKey.pubKey, newKey.pubKey)
        self.assertEqual(extKey.chainCode, newKey.chainCode)
        self.assertEqual(extKey.parentFP, newKey.parentFP)
        self.assertEqual(extKey.depth, newKey.depth)
        self.assertEqual(extKey.childNum, newKey.childNum)
        self.assertEqual(extKey.isPrivate, newKey.isPrivate)
    def test_child(self):
        extKey = newMaster(ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b, mainnet)
        kid = extKey.child(0)
        pub = extKey.neuter()
        self.assertEqual(pub.string(), "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbRqbfTCJ9BUnWPCkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk")
        addr = pub.deriveChildAddress(5, mainnet)
        print("--addr: %s", addr)
    def test_address_manager(self):
        pw = "abc".encode("ascii")
        am = createNewAccountManager(ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b, bytearray(0), pw, mainnet)
        rekey = am.acctPrivateKey(0, mainnet, pw)
        pubFromPriv = rekey.neuter()
        addr1 = pubFromPriv.deriveChildAddress(5, mainnet)
        pubKey = am.acctPublicKey(0, mainnet, "")
        addr2 = pubKey.deriveChildAddress(5, mainnet)
        self.assertEqual(addr1, addr2)
        acct = am.openAccount(0, mainnet, pw)

        for n in range(20):
            print("address %i: %s" % (n, acct.getNthPaymentAddress(n)))
    def test_new_master(self):
        b = ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        extKey = newMaster(b.b, mainnet)
    def test_change_addresses(self):
        pw = "abc".encode("ascii")
        acctManager = createNewAccountManager(ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b, bytearray(0), pw, mainnet)
        acct = acctManager.account(0)
        for i in range(10):
            addr = acct.getChangeAddress()
            print("change address %i: %s" % (i, addr))
    def test_signatures(self):
        pw = "abc".encode("ascii")
        am = createNewAccountManager(ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b, bytearray(0), pw, mainnet)
        acct = am.openAccount(0, mainnet, pw)

        print("\n")
        addr1 = acct.generateNextPaymentAddress()
        print("--addr1: %s" % addr1)

        privKey = acct.getPrivKeyForAddress(addr1)
        pkBytes = privKey.pub.serializeCompressed()

        print("--pkBytes: %s" % pkBytes.hex())

        addr2 = addressForPubkeyBytes(pkBytes.bytes(), mainnet)
        print("--addr2: %s" % addr2)


        # # OP_DUP OP_HASH160 9905a4df9d118e0e495d2bb2548f1f72bc1f3058 OP_EQUALVERIFY OP_CHECKSIG
        # addr = txscript.Address(netID=simnet.PubKeyHashAddrID, pkHash=ByteArray("9905a4df9d118e0e495d2bb2548f1f72bc1f3058"))
        # print("--readdress: %s" % addr.string())



        # privKey = acctKey.privateKey()
        # pubKey = privKey.pub

        # # key = ByteArray("eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694")
        # # pk = privKeyFromBytes(key)

        # inHash = ByteArray("00010203040506070809")
        # sig = txscript.signRFC6979(privKey.key, inHash)
        # self.assertTrue(txscript.verifySig(pubKey, inHash.b, sig.r, sig.s))
    def test_extended_key(self):
        seed = ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        kpriv = newMaster(seed.b, mainnet)
        print("--extKey: %s" % kpriv.key.hex())
    def test_test(self):
        pubkey = ByteArray("047df0587352cb46b94ac2ab71acb1f62129f2e0a5218da8ea3b7259439969b0a49a678a9a5a43de2c60686c38547fb6a1d88cbabb390e5bdfb81a91726496392b")
        print(crypto.hash160(pubkey.b).hex())

        pkHash = ByteArray("6b3b90b8420dc1f82b4624e062f080ba3b442d9b")
        address = addressForPubkeyBytes(pkHash.b, simnet)
        print("--address: %s" % address)

        addr2 = txscript.pubKeyHashToAddrs(pkHash, simnet)[0].string()
        print("--addr2: %s" % addr2)

        # kpub = kpriv.neuter()
        # print("--kpub: %s" % kpub.key.hex())
        # kpub_branch0 = kpub.child(0)
        # print("--kpub_branch0: %s" % kpub_branch0.key.hex())
        # kpub_branch0_child1 = kpub_branch0.child(1)
        # print("--kpub_branch0_child1: %s" % kpub_branch0_child1.key.hex())
        # kpriv_branch0 = kpriv.child(0)
        # print("--kpriv_branch0: %s" % kpriv_branch0.key.hex())
        # kpriv_branch0_child1 = kpriv_branch0.child(1)
        # print("--kpriv_branch0_child1: %s" % kpriv_branch0_child1.key.hex())

        # pubFromPriv_pub = kpriv_branch0_child1.publicKey()
        # pubFromPriv_priv = kpriv_branch0_child1.privateKey().pub
        # pubFromPub_pub = kpub_branch0_child1.publicKey()

        # print("--pubFromPriv_pub: %s" % pubFromPriv_pub.serializeUncompressed().hex())
        # print("--pubFromPriv_priv: %s" % pubFromPriv_priv.serializeUncompressed().hex())
        # print("--pubFromPub_pub: %s" % pubFromPub_pub.serializeUncompressed().hex())

        # addrFromBytes = txscript.newAddressPubKeyHash(crypto.hash160(kpriv_branch0_child1.pubKey.bytes()), mainnet, crypto.STEcdsaSecp256k1).string()
        # addrFromDerive = kpub_branch0.deriveChildAddress(1,  mainnet)
        # print("--addrFromBytes: %s" % addrFromBytes)
        # print("--addrFromDerive: %s" % addrFromDerive)






if __name__ == "__main__":
    pass