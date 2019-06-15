"""
Much inspiration from https://github.com/decred/dcrd/blob/master/dcrec/secp256k1
"""
from tinydecred.pydecred import dcrjson as json, mainnet, helpers
from tinydecred.pydecred import constants as C
from tinydecred.crypto import crypto
from tinydecred.crypto.rando import generateSeed
from tinydecred.crypto.bytearray import ByteArray
import unittest
import hashlib
import hmac

EXTERNAL_BRANCH = 0
INTERNAL_BRANCH = 1
MASTER_KEY = b"Bitcoin seed"
MAX_SECRET_INT = 115792089237316195423570985008687907852837564279074904382605163141518161494337
# S256_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
# S256_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
SALT_SIZE = 32
DEFAULT_ACCOUNT_NAME = "default"

log = helpers.getLogger("TCRYP") #, logLvl=0)

class KeyLengthException(Exception):
    pass
class ParameterRangeError(Exception):
    pass

def newMaster(seed, network):
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

# coinTypes returns the legacy and SLIP0044 coin types for the chain
# parameters.  At the moment, the parameters have not been upgraded for the new
# coin types.
def coinTypes(params):
    return params.LegacyCoinType, params.SLIP0044CoinType

# checkBranchKeys ensures deriving the extended keys for the internal and
# external branches given an account key does not result in an invalid child
# error which means the chosen seed is not usable.  This conforms to the
# hierarchy described by BIP0044 so long as the account key is already derived
# accordingly.
#
# In particular this is the hierarchical deterministic extended key path:
#   m/44'/<coin type>'/<account>'/<branch>
#
# The branch is 0 for external addresses and 1 for internal addresses.
def checkBranchKeys(acctKey):
    """
    Try to raise an exception.
    """
    # Derive the external branch as the first child of the account key.
    acctKey.child(EXTERNAL_BRANCH)

    # Derive the interal branch as the second child of the account key.
    acctKey.child(INTERNAL_BRANCH)

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
        self.db = {
            "tx": {}, # {address: [txid1, txid2, ..]}
            "utxo" : {}, # {address: [(txid1, idx1), (txid2, idx2)]}
        }
        # If the accounts privKey is set with the private extended key
        # the account is considered "open". close'ing the wallet zeros
        # and drops reference to the privKey. 
        self.privKey = None
        self.extPub = None
        self.intPub = None
        self.generateSalt()
    def transactions(self, addr=None):
        txs = self.db["tx"]
        if addr and addr in txs:
            return txs[addr]
        if not addr:
            return txs
        txs[addr] = {}
        return txs[addr]
    def utxos(self, addr=None):
        utxos = self.db["utxo"]
        if addr and addr in utxos:
            return utxos[addr]
        if not addr:
            return utxos
        utxos[addr] = {}
        return utxos[addr]
    def utxoscan(self):
        for addr, utxos in self.db["utxo"].items():
            for utxo in utxos.values():
                yield utxo
    def __tojson__(self):
        return {
            "pubKeyEncrypted": self.pubKeyEncrypted,
            "privKeyEncrypted": self.privKeyEncrypted,
            "lastExternalIndex": self.lastExternalIndex,
            "lastInternalIndex": self.lastInternalIndex,
            "name": self.name,
            "externalAddresses": self.externalAddresses,
            "internalAddresses": self.internalAddresses,
            "db": self.db,
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
        return acct
    def getNextPaymentAddress(self):
        if len(self.externalAddresses) != self.lastExternalIndex + 1:
            raise Exception("index-address length mismatch")
        idx = self.lastExternalIndex + 1
        addr = self.extPub.deriveChildAddress(idx, self.net)
        self.externalAddresses.append(addr)
        self.lastExternalIndex = idx
        return addr
    def getChangeAddress(self):
        if len(self.internalAddresses) != self.lastInternalIndex + 1:
            raise Exception("index-address length mismatch while generating change address")
        idx = self.lastInternalIndex + 1
        addr = self.intPub.deriveChildAddress(idx, self.net)
        self.internalAddresses.append(addr)
        self.lastInternalIndex = idx
        return addr
    def getNthPaymentAddress(self, n):
        return self.extPub.deriveChildAddress(n, self.net)
    def paymentAddress(self):
        return self.externalAddresses[self.lastExternalIndex]
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

    # Save the information for the default account to the database.  This
    # account is derived from the legacy coin type.
    baseAccount = Account(acctPubLegacyEnc, acctPrivLegacyEnc, DEFAULT_ACCOUNT_NAME)

    # Save the account row for the 0th account derived from the coin type
    # 42 key.
    zerothAccount = Account(acctPubSLIP0044Enc, acctPrivSLIP0044Enc, DEFAULT_ACCOUNT_NAME)
    # Open the account
    zerothAccount.open(chainParams, cryptoKeyPriv)
    # Create the first payment address
    zerothAccount.getNextPaymentAddress()
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
        b = ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", mainnet)
        extKey = newMaster(b.b, mainnet)
    def test_change_addresses(self):
        pw = "abc".encode("ascii")
        acctManager = createNewAccountManager(ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b, bytearray(0), pw, mainnet)
        acct = acctManager.account(0)
        for i in range(10):
            addr = acct.getChangeAddress()
            print("change address %i: %s" % (i, addr))


if __name__ == "__main__":
    pass