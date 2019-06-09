"""
Much inspiration from https://github.com/decred/dcrd/blob/master/dcrec/secp256k1
"""
from pydecred import json, mainnet
import crypto
from crypto.rando import generateSeed
from crypto.bytearray import ByteArray
from two1.crypto import ecdsa
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
# SHA256_SIZE = 32
DEFAULT_ACCOUNT_NAME = "default"

Curve = ecdsa.secp256k1()


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


# // createAddressManager creates a new address manager in the given namespace.
# // The seed must conform to the standards described in hdkeychain.NewMaster and
# // will be used to create the master root node from which all hierarchical
# // deterministic addresses are derived.  This allows all chained addresses in
# // the address manager to be recovered by using the same seed.
# //
# // All private and public keys and information are protected by secret keys
# // derived from the provided private and public passphrases.  The public
# // passphrase is required on subsequent opens of the address manager, and the
# // private passphrase is required to unlock the address manager in order to gain
# // access to any private keys and information.
# func createAddressManager(ns walletdb.ReadWriteBucket, seed, pubPassphrase, privPassphrase []byte, chainParams *chaincfg.Params, config *ScryptOptions) error {
# 	// Return an error if the manager has already been created in the given
# 	// database namespace.
# 	if managerExists(ns) {
# 		return errors.E(errors.Exist, "address manager already exists")
# 	}

# 	// Ensure the private passphrase is not empty.
# 	if len(privPassphrase) == 0 {
# 		return errors.E(errors.Invalid, "private passphrase may not be empty")
# 	}

# 	// Perform the initial bucket creation and database namespace setup.
# 	if err := createManagerNS(ns); err != nil {
# 		return err
# 	}

# 	// Generate the BIP0044 HD key structure to ensure the provided seed
# 	// can generate the required structure with no issues.

# 	// Derive the master extended key from the seed.
# 	root, err := hdkeychain.NewMaster(seed, chainParams)
# 	if err != nil {
# 		return err
# 	}

# 	// Derive the cointype keys according to BIP0044.
# 	legacyCoinType, slip0044CoinType := coinTypes(chainParams)
# 	coinTypeLegacyKeyPriv, err := deriveCoinTypeKey(root, legacyCoinType)
# 	if err != nil {
# 		return err
# 	}
# 	defer coinTypeLegacyKeyPriv.Zero()
# 	coinTypeSLIP0044KeyPriv, err := deriveCoinTypeKey(root, slip0044CoinType)
# 	if err != nil {
# 		return err
# 	}
# 	defer coinTypeSLIP0044KeyPriv.Zero()

# 	// Derive the account key for the first account according to BIP0044.
# 	acctKeyLegacyPriv, err := deriveAccountKey(coinTypeLegacyKeyPriv, 0)
# 	if err != nil {
# 		// The seed is unusable if the any of the children in the
# 		// required hierarchy can't be derived due to invalid child.
# 		if err == hdkeychain.ErrInvalidChild {
# 			return errors.E(errors.Seed, hdkeychain.ErrUnusableSeed)
# 		}

# 		return err
# 	}
# 	acctKeySLIP0044Priv, err := deriveAccountKey(coinTypeSLIP0044KeyPriv, 0)
# 	if err != nil {
# 		// The seed is unusable if the any of the children in the
# 		// required hierarchy can't be derived due to invalid child.
# 		if err == hdkeychain.ErrInvalidChild {
# 			return errors.E(errors.Seed, hdkeychain.ErrUnusableSeed)
# 		}

# 		return err
# 	}

# 	// Ensure the branch keys can be derived for the provided seed according
# 	// to BIP0044.
# 	if err := checkBranchKeys(acctKeyLegacyPriv); err != nil {
# 		// The seed is unusable if the any of the children in the
# 		// required hierarchy can't be derived due to invalid child.
# 		if err == hdkeychain.ErrInvalidChild {
# 			return errors.E(errors.Seed, hdkeychain.ErrUnusableSeed)
# 		}

# 		return err
# 	}
# 	if err := checkBranchKeys(acctKeySLIP0044Priv); err != nil {
# 		// The seed is unusable if the any of the children in the
# 		// required hierarchy can't be derived due to invalid child.
# 		if err == hdkeychain.ErrInvalidChild {
# 			return errors.E(errors.Seed, hdkeychain.ErrUnusableSeed)
# 		}

# 		return err
# 	}

# 	// The address manager needs the public extended key for the account.
# 	acctKeyLegacyPub, err := acctKeyLegacyPriv.Neuter()
# 	if err != nil {
# 		return err
# 	}
# 	acctKeySLIP0044Pub, err := acctKeySLIP0044Priv.Neuter()
# 	if err != nil {
# 		return err
# 	}

# 	// Generate new master keys.  These master keys are used to protect the
# 	// crypto keys that will be generated next.
# 	masterKeyPub, err := newSecretKey(&pubPassphrase, config)
# 	if err != nil {
# 		return err
# 	}
# 	masterKeyPriv, err := newSecretKey(&privPassphrase, config)
# 	if err != nil {
# 		return err
# 	}
# 	defer masterKeyPriv.Zero()

# 	// Generate the private passphrase salt.  This is used when hashing
# 	// passwords to detect whether an unlock can be avoided when the manager
# 	// is already unlocked.
# 	var privPassphraseSalt [saltSize]byte
# 	_, err = rand.Read(privPassphraseSalt[:])
# 	if err != nil {
# 		return errors.E(errors.IO, err)
# 	}

# 	// Generate new crypto public, private, and script keys.  These keys are
# 	// used to protect the actual public and private data such as addresses,
# 	// extended keys, and scripts.
# 	cryptoKeyPub, err := newCryptoKey()
# 	if err != nil {
# 		return err
# 	}
# 	cryptoKeyPriv, err := newCryptoKey()
# 	if err != nil {
# 		return err
# 	}
# 	defer cryptoKeyPriv.Zero()

# 	cryptoKeyScript, err := newCryptoKey()
# 	if err != nil {
# 		return err
# 	}
# 	defer cryptoKeyScript.Zero()

# 	// Encrypt the crypto keys with the associated master keys.
# 	cryptoKeyPubEnc, err := masterKeyPub.Encrypt(cryptoKeyPub.Bytes())
# 	if err != nil {
# 		return errors.E(errors.Crypto, errors.Errorf("encrypt crypto pubkey: %v", err))
# 	}
# 	cryptoKeyPrivEnc, err := masterKeyPriv.Encrypt(cryptoKeyPriv.Bytes())
# 	if err != nil {
# 		return errors.E(errors.Crypto, errors.Errorf("encrypt crypto privkey: %v", err))
# 	}
# 	cryptoKeyScriptEnc, err := masterKeyPriv.Encrypt(cryptoKeyScript.Bytes())
# 	if err != nil {
# 		return errors.E(errors.Crypto, errors.Errorf("encrypt crypto script key: %v", err))
# 	}

# 	// Encrypt the legacy cointype keys with the associated crypto keys.
# 	coinTypeLegacyKeyPub, err := coinTypeLegacyKeyPriv.Neuter()
# 	if err != nil {
# 		return err
# 	}
# 	ctpes := coinTypeLegacyKeyPub.String()
# 	coinTypeLegacyPubEnc, err := cryptoKeyPub.Encrypt([]byte(ctpes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt legacy cointype pubkey: %v", err))
# 	}
# 	ctpes = coinTypeLegacyKeyPriv.String()
# 	coinTypeLegacyPrivEnc, err := cryptoKeyPriv.Encrypt([]byte(ctpes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt legacy cointype privkey: %v", err))
# 	}

# 	// Encrypt the SLIP0044 cointype keys with the associated crypto keys.
# 	coinTypeSLIP0044KeyPub, err := coinTypeSLIP0044KeyPriv.Neuter()
# 	if err != nil {
# 		return err
# 	}
# 	ctpes = coinTypeSLIP0044KeyPub.String()
# 	coinTypeSLIP0044PubEnc, err := cryptoKeyPub.Encrypt([]byte(ctpes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt SLIP0044 cointype pubkey: %v", err))
# 	}
# 	ctpes = coinTypeSLIP0044KeyPriv.String()
# 	coinTypeSLIP0044PrivEnc, err := cryptoKeyPriv.Encrypt([]byte(ctpes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt SLIP0044 cointype privkey: %v", err))
# 	}

# 	// Encrypt the default account keys with the associated crypto keys.
# 	apes := acctKeyLegacyPub.String()
# 	acctPubLegacyEnc, err := cryptoKeyPub.Encrypt([]byte(apes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 pubkey: %v", err))
# 	}
# 	apes = acctKeyLegacyPriv.String()
# 	acctPrivLegacyEnc, err := cryptoKeyPriv.Encrypt([]byte(apes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 privkey: %v", err))
# 	}
# 	apes = acctKeySLIP0044Pub.String()
# 	acctPubSLIP0044Enc, err := cryptoKeyPub.Encrypt([]byte(apes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 pubkey: %v", err))
# 	}
# 	apes = acctKeySLIP0044Priv.String()
# 	acctPrivSLIP0044Enc, err := cryptoKeyPriv.Encrypt([]byte(apes))
# 	if err != nil {
# 		return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 privkey: %v", err))
# 	}

# 	// Save the master key params to the database.
# 	pubParams := masterKeyPub.Marshal()
# 	privParams := masterKeyPriv.Marshal()
# 	err = putMasterKeyParams(ns, pubParams, privParams)
# 	if err != nil {
# 		return err
# 	}

# 	// Save the encrypted crypto keys to the database.
# 	err = putCryptoKeys(ns, cryptoKeyPubEnc, cryptoKeyPrivEnc,
# 		cryptoKeyScriptEnc)
# 	if err != nil {
# 		return err
# 	}

# 	// Save the encrypted legacy cointype keys to the database.
# 	err = putCoinTypeLegacyKeys(ns, coinTypeLegacyPubEnc, coinTypeLegacyPrivEnc)
# 	if err != nil {
# 		return err
# 	}

# 	// Save the encrypted SLIP0044 cointype keys.
# 	err = putCoinTypeSLIP0044Keys(ns, coinTypeSLIP0044PubEnc, coinTypeSLIP0044PrivEnc)
# 	if err != nil {
# 		return err
# 	}

# 	// Save the fact this is not a watching-only address manager to the
# 	// database.
# 	err = putWatchingOnly(ns, false)
# 	if err != nil {
# 		return err
# 	}

# 	// Set the next to use addresses as empty for the address pool.
# 	err = putNextToUseAddrPoolIdx(ns, false, DefaultAccountNum, 0)
# 	if err != nil {
# 		return err
# 	}
# 	err = putNextToUseAddrPoolIdx(ns, true, DefaultAccountNum, 0)
# 	if err != nil {
# 		return err
# 	}

# 	// Save the information for the imported account to the database.  Even
# 	// though the imported account is a special and restricted account, the
# 	// database used a BIP0044 row type for it.
# 	importedRow := bip0044AccountInfo(nil, nil, 0, 0, 0, 0, 0, 0,
# 		ImportedAddrAccountName, initialVersion)
# 	err = putAccountInfo(ns, ImportedAddrAccount, importedRow)
# 	if err != nil {
# 		return err
# 	}

# 	// Save the information for the default account to the database.  This
# 	// account is derived from the legacy coin type.
# 	defaultRow := bip0044AccountInfo(acctPubLegacyEnc, acctPrivLegacyEnc,
# 		0, 0, 0, 0, 0, 0, defaultAccountName, initialVersion)
# 	err = putAccountInfo(ns, DefaultAccountNum, defaultRow)
# 	if err != nil {
# 		return err
# 	}

# 	// Save the account row for the 0th account derived from the coin type
# 	// 42 key.
# 	slip0044Account0Row := bip0044AccountInfo(acctPubSLIP0044Enc, acctPrivSLIP0044Enc,
# 		0, 0, 0, 0, 0, 0, defaultAccountName, initialVersion)
# 	mainBucket := ns.NestedReadWriteBucket(mainBucketName)
# 	err = mainBucket.Put(slip0044Account0RowName, serializeAccountRow(&slip0044Account0Row.dbAccountRow))
# 	if err != nil {
# 		return errors.E(errors.IO, err)
# 	}

# 	return nil
# }

class Account:
    def __init__(self, pubKeyEncrypted, privKeyEncrypted, lastExternalIndex, lastInternalIndex, name):
        self.pubKeyEncrypted = pubKeyEncrypted
        self.privKeyEncrypted = privKeyEncrypted
        self.lastExternalIndex = lastExternalIndex
        self.lastInternalIndex = lastInternalIndex
        self.name = name
    def __tojson__(self):
        return {
            "pubKeyEncrypted": self.pubKeyEncrypted,
            "privKeyEncrypted": self.privKeyEncrypted,
            "lastExternalIndex": self.lastExternalIndex,
            "lastInternalIndex": self.lastInternalIndex,
            "name": self.name,
        }
    @staticmethod
    def __fromjson__(obj):
        return Account(
            obj["pubKeyEncrypted"],
            obj["privKeyEncrypted"],
            obj["lastExternalIndex"],
            obj["lastInternalIndex"],
            obj["name"],
        )
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
		self.generateSalt()
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
		manager.generateSalt()
		return manager
	def generateSalt(self):
		self.privPassphraseSalt = ByteArray(generateSeed(SALT_SIZE))
	def addAccount(self, account):
		self.accounts.append(account)
	def privateExtendedKey(self, net, pw):
		userSecret = crypto.SecretKey.rekey(pw, self.privParams)
		cryptKeyPriv = ByteArray(userSecret.decrypt(self.cryptoKeyPrivEnc.bytes()))
		return crypto.decodeExtendedKey(net, cryptKeyPriv, self.coinTypeSLIP0044PrivEnc)
	def publicExtendedKey(self, net, pw):
		userSecret = crypto.SecretKey.rekey(pw, self.pubParams)
		cryptKeyPub = ByteArray(userSecret.decrypt(self.cryptoKeyPubEnc.bytes()))
		return crypto.decodeExtendedKey(net, cryptKeyPub, self.coinTypeSLIP0044PubEnc)

json.register(AccountManager)

def createNewAccountManager(seed, pubPassphrase, privPassphrase, chainParams, config):
	"""
	ns walletdb.ReadWriteBucket
	seed, pubPassphrase, privPassphrase []byte
	chainParams *chaincfg.Params
	config *ScryptOptions
	"""
	# # Return an error if the manager has already been created in the given
	# # database namespace.
	# if managerExists(ns) {
	# 	return errors.E(errors.Exist, "address manager already exists")
	# }

	# Ensure the private passphrase is not empty.
	if len(privPassphrase) == 0:
		raise Exception("createAddressManager: private passphrase cannot be empty")


# 	// Perform the initial bucket creation and database namespace setup.
# 	if err := createManagerNS(ns); err != nil {
# 		return err
# 	}

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
# 	defer cryptoKeyPriv.Zero()

	cryptoKeyScript = ByteArray(generateSeed(crypto.KEY_SIZE))
# 	defer cryptoKeyScript.Zero()

# 	// Encrypt the crypto keys with the associated master keys.
	cryptoKeyPubEnc = masterKeyPub.encrypt(cryptoKeyPub.b)

	cryptoKeyPrivEnc = masterKeyPriv.encrypt(cryptoKeyPriv.b)

	cryptoKeyScriptEnc = masterKeyPriv.encrypt(cryptoKeyScript.b)

	# Encrypt the legacy cointype keys with the associated crypto keys.
	coinTypeLegacyKeyPub = coinTypeLegacyKeyPriv.neuter()

	# try to raise a couple of exceptions
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
	# testMaster = SecretKey(privPassphrase)
	testKey = ByteArray(masterKeyPriv.decrypt(cryptoKeyPrivEnc.bytes()))
	testKey.decrypt(coinTypeSLIP0044PrivEnc.bytes())

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
	baseAccount = Account(acctPubLegacyEnc, acctPrivLegacyEnc, 0, 0, DEFAULT_ACCOUNT_NAME)

	# Save the account row for the 0th account derived from the coin type
	# 42 key.
	zerothAccount = Account(acctPubSLIP0044Enc, acctPrivSLIP0044Enc, 0, 0, DEFAULT_ACCOUNT_NAME)

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
	def test_encode_decode(self):
		extKey = newMaster(generateSeed(), mainnet)
		# print(extKey.privVer)
		# print(extKey.privVer.__tojson__())
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
		pub = extKey.neuter()
		self.assertEqual(pub.string(), "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbRqbfTCJ9BUnWPCkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk")
		addr = pub.deriveChildAddress(5, mainnet)
		print("--addr: %s" % addr)
	def test_address_manager(self):
		am = createNewAccountManager(ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").b, bytearray(0), "abc".encode("ascii"), mainnet, {})
		rekey = am.publicExtendedKey(mainnet, b'')
	def test_new_master(self):
		b = ByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", mainnet)
		extKey = newMaster(b.b, mainnet)
		print(extKey.string())


if __name__ == "__main__":
	pass