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
from tinydecred.util import tinyjson, helpers
from tinydecred.wallet import api
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

# See CrazyKeyError docs. When an out-of-range key is created, a placeholder
# is set for that child's position internally in Account.
CrazyAddress = "CRAZYADDRESS"

def filterCrazyAddress(addrs):
    """
    When addresses are read out in bulk, they should be filtered for the
    CrazyAddress.
    """
    return [a for a in addrs if a != CrazyAddress]

# DefaultGapLimit is the default unused address gap limit defined by BIP0044.
DefaultGapLimit = 20

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
    The ExtendedKey created and any children created through its interface are
    specific to the network provided. The extended key returned from newMaster
    can be used to generate coin-type and account keys in accordance with
    BIP-0032 and BIP-0044.

    Args:
        seed (bytes-like): A random seed from which the extended key is made.
        network (obj): an object with BIP32 hierarchical deterministic extended
            key magics as attributes `HDPrivateKeyID` and `HDPublicKeyID`.

    Returns:
        crypto.ExtendedKey: A master hierarchical deterministic key.
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

    # Ensure the key is usable.
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
    parameters. At the moment, the parameters have not been upgraded for the new
    coin types.

    Args:
        params (obj): Network parameters.

    Returns
        int: Legacy coin type.
        int: SLIP0044 coin type.
    """
    return params.LegacyCoinType, params.SLIP0044CoinType

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
        # For external addresses, the cursor can sit on the last seen address,
        # so start the lastSeen at the 0th external address. This is necessary
        # because the currentAddress method grabs the address at the current
        # cursor position, rather than the next.
        self.lastSeenExt = 0
        # For internal addresses, the cursor can sit below zero, since the
        # addresses are always retrieved with nextInternalAddress.
        self.lastSeenInt = -1
        self.externalAddresses = []
        self.internalAddresses = []
        self.cursorExt = 0
        self.cursorInt = 0
        self.balance = Balance()
        # Map a txid to a MsgTx for a transaction suspected of being in
        # mempool.
        self.mempool = {}
        # txs maps a base58 encoded address to a list of txid.
        self.txs = {}
        # utxos is a mapping of utxo key ({txid}#{vout}) to a UTXO.
        self.utxos = {}
        # If the account's privKey is set with the private extended key the
        # account is considered "open". Closing the wallet zeros and drops
        # reference to the privKey.
        self.privKey = None # The private extended key.
        self.extPub = None # The external branch public extended key.
        self.intPub = None # The internal branch public extended key.
        self.gapLimit = DefaultGapLimit
    def __tojson__(self):
        return {
            "pubKeyEncrypted": self.pubKeyEncrypted,
            "privKeyEncrypted": self.privKeyEncrypted,
            "name": self.name,
            "coinID": self.coinID,
            "netID": self.netID,
            "externalAddresses": self.externalAddresses,
            "internalAddresses": self.internalAddresses,
            "cursorExt": self.cursorExt,
            "cursorInt": self.cursorInt,
            "txs": self.txs,
            "utxos": self.utxos,
            "balance": self.balance,
            "gapLimit": self.gapLimit,
        }
    @staticmethod
    def __fromjson__(obj, cls=None):
        cls = cls if cls else Account
        acct = cls(
            obj["pubKeyEncrypted"],
            obj["privKeyEncrypted"],
            obj["name"],
            obj["coinID"],
            obj["netID"],
        )
        acct.externalAddresses = obj["externalAddresses"]
        acct.internalAddresses = obj["internalAddresses"]
        acct.cursorExt = obj["cursorExt"]
        acct.cursorInt = obj["cursorInt"]
        acct.txs = obj["txs"]
        acct.utxos = obj["utxos"]
        acct.balance = obj["balance"]
        acct.gapLimit = obj["gapLimit"]
        acct.lastSeenExt = acct.lastSeen(acct.externalAddresses)
        acct.lastSeenInt = acct.lastSeen(acct.internalAddresses)
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

        Returns:
            UTXO: The UTXO if found or None.
        """
        uKey =  UTXO.makeKey(txid,  vout)
        return self.utxos[uKey] if uKey in self.utxos else None
    def caresAboutTxid(self, txid):
        """
        Indicates whether the account has any UTXOs with this transaction ID, or
        has this transaction in mempool.

        Args:
            txid (str): The hex-encoded transaction ID.

        Returns:
            bool: `True` if we are watching the txid.
        """
        return txid in self.mempool or self.hasUTXOwithTXID(txid)
    def hasUTXOwithTXID(self, txid):
        """
        Search watched transaction ids for txid.

        Args:
            txid (str): The hex-encoded transaction ID.

        Returns:
            bool: `True` if found.
        """
        for utxo in self.utxos.values():
            if utxo.txid == txid:
                return True
        return False
    def UTXOsForTXID(self, txid):
        """
        Get any UTXOs with the provided transaction ID.

        Args:
            txid (str): The hex-encoded transaction ID.

        Returns:
            list(UTXO): List of UTXO for the txid.
        """
        return [utxo for utxo in self.utxoscan() if utxo.txid == txid]
    def spendUTXOs(self, utxos):
        """
        Spend the UTXOs.

        Args:
            utxos list(UTXO): The UTXOs to spend.
        """
        for utxo in utxos:
            self.spendUTXO(utxo)
    def spendUTXO(self, utxo):
        """
        Spend the UTXO. The UTXO is removed from the watched list and returned.

        Args:
            utxo (UTXO): The UTXO to spend.

        Returns:
            UTXO: The spent UTXO.
        """
        return self.utxos.pop(utxo.key(), None)
    def resolveUTXOs(self, blockchainUTXOs):
        """
        Populate self.utxos from blockchainUTXOs.

        Args:
            blockchainUTXOs dict(UTXO): dictionary of UTXOs to set self.utxos
                to.
        """
        self.utxos = {u.key(): u for u in blockchainUTXOs}
    def getUTXOs(self, requested, approve=None):
        """
        Find confirmed and mature UTXOs, smallest first, that sum to the
        requested amount, in atoms.

        Args:
            requested (int): Required amount in atoms.
            approve (func(UTXO) -> bool): Optional UTXO filtering function.

        Returns:
            list(UTXO): A list of UTXOs.
            bool: True if the UTXO sum is >= the requested amount.
        """
        matches = []
        collected = 0
        pairs = [(u.satoshis, u) for u in self.utxoscan()]
        for v, utxo in sorted(pairs, key=lambda p: p[0]):
            if approve and not approve(utxo):
                continue
            matches.append(utxo)
            collected += v
            if collected >= requested:
                break
        return matches, collected >= requested
    def spendTxidVout(self, txid, vout):
        """
        Spend the UTXO. The UTXO is removed from the watched list and returned.

        Args:
            txid (str): The hex-encoded transaction ID.
            vout (int): The transaction output index.

        Returns:
            UTXO: The spent UTXO.
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
        """
        Add addr and txid to tracked addresses and txids if not already added.

        Args:
            addr (str): Base-58 encoded address.
            txid (str): The hex-encoded transaction ID.
        """
        if not addr in self.txs:
            self.txs[addr] = []
        txids = self.txs[addr]
        if txid not in txids:
            txids.append(txid)
        # Advance the cursors as necessary.
        if addr in self.externalAddresses:
            extIdx = self.externalAddresses.index(addr)
            if extIdx > self.lastSeenExt:
                diff = extIdx - self.lastSeenExt
                self.lastSeenExt = extIdx
                self.cursorExt = max(0, self.cursorExt-diff)
        elif addr in self.internalAddresses:
            intIdx = self.internalAddresses.index(addr)
            if intIdx > self.lastSeenInt:
                diff = intIdx - self.lastSeenInt
                self.lastSeenInt = intIdx
                self.cursorInt = max(0, self.cursorInt-diff)
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
                # This is a coinbase transaction, set the maturity height.
                utxo.maturity = utxo.height + self.net.CoinbaseMaturity
            # else:
            #     utxo.maturity = utxo.height + 1 # Not sure about this
    def calcBalance(self, tipHeight):
        """
        Calculate the balance. The current height must be provided to separate
        UTXOs which are not mature.

        Args:
            tipHeight (int): The current best block height.

        Returns:
            Balance: The current account balance.
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
    def nextBranchAddress(self, branchKey, branchAddrs):
        """
        Generate a new address and add it to the list of external addresses.
        Does not move the cursor.

        Args:
            branchKey (ExtendedKey): The branch extended public key.
            branchAddrs (list(string)): The current list of branch addresses.

        Returns:
            str: Base-58 encoded address.
        """
        for i in range(3):
            try:
                addr = branchKey.deriveChildAddress(len(branchAddrs), self.net)
                branchAddrs.append(addr)
                return addr
            except crypto.CrazyKeyError:
                log.warning("crazy address generated")
                addr = CrazyAddress
                branchAddrs.append(addr)
                continue
        raise Exception("failed to generate new address")
    def nextExternalAddress(self):
        """
        Return a new external address by advancing the cursor.

        Returns:
            addr (str): Base-58 encoded address.
        """
        extAddrs = self.externalAddresses
        addr = CrazyAddress
        # Though unlikely, if an out or range key is generated, the account will
        # generate an additional address
        while addr == CrazyAddress:
            # gap policy is to wrap. Wrapping brings the cursor back to index 1,
            # since the index zero is the last seen address.
            self.cursorExt += 1
            if self.cursorExt > self.gapLimit:
                self.cursorExt = 1
            idx = self.lastSeenExt + self.cursorExt
            while len(extAddrs) < idx + 1:
                self.nextBranchAddress(self.extPub, extAddrs)
            addr = extAddrs[idx]
        return addr
    def nextInternalAddress(self):
        """
        Return a new internal address

        Returns:
            str: Base-58 encoded address.
        """
        intAddrs = self.internalAddresses
        addr = CrazyAddress
        # Though unlikely, if an out or range key is generated, the account will
        # generate an additional address
        while addr == CrazyAddress:
            # gap policy is to wrap. Wrapping brings the cursor back to index 1,
            # since the index zero is the last seen address.
            self.cursorInt += 1
            if self.cursorInt > self.gapLimit:
                self.cursorInt = 1
            idx = self.lastSeenInt + self.cursorInt
            while len(intAddrs) < idx + 1:
                self.nextBranchAddress(self.intPub, intAddrs)
            addr = intAddrs[idx]
        return addr
    def lastSeen(self, addrs):
        """
        Find the index of the last seen address in the list of addresses.
        The last seen address is taken as the last address for which there is an
        entry in the self.txs dict.

        Args:
            addrs (list(string)): The list of addresses.

        Returns:
            int: The highest index of all seen addresses in the list.
        """
        lastSeen = -1
        for i, addr in enumerate(addrs):
            if addr in self.txs:
                lastSeen = i
        return lastSeen
    def generateGapAddresses(self):
        """
        Generate addresses up to gap addresses after the cursor. Do not move the
        cursor.

        Args:
            gap (int): Number of addresses to generate past the current cursor.
        """
        if self.extPub is None:
            log.warning("attempting to generate gap addresses on a closed account")
        newAddrs = []
        extAddrs, intAddrs = self.externalAddresses, self.internalAddresses
        minExtLen = self.lastSeenExt + self.gapLimit + 1
        while len(extAddrs) < minExtLen:
            self.nextBranchAddress(self.extPub, extAddrs)
            newAddrs.append(extAddrs[len(extAddrs)-1])
        minIntLen = self.lastSeenInt + self.gapLimit + 1
        while len(intAddrs) < minIntLen:
            self.nextBranchAddress(self.intPub, self.internalAddresses)
            newAddrs.append(intAddrs[len(intAddrs)-1])
        return newAddrs
    def allAddresses(self):
        """
        Get the list of all known addresses for this account.

        Returns:
            list(str): A list of base-58 encoded addresses.
        """
        return filterCrazyAddress(self.internalAddresses + self.externalAddresses)
    def watchAddrs(self):
        """
        Scan and get the list of all known addresses for this account.

        Returns:
            list(str): A list of base-58 encoded addresses.
        """
        a = set()
        a = a.union((utxo.address for utxo in self.utxoscan()))
        a = a.union(self.externalAddresses)
        a = a.union((a for a in self.internalAddresses if a not in self.txs))
        return filterCrazyAddress(a)
    def unseenAddrs(self):
        return filterCrazyAddress(
            [a for a in self.internalAddresses if a not in self.txs] +
            [a for a in self.externalAddresses if a not in self.txs])
    def currentAddress(self):
        """
        Get the external address at the cursor. The cursor is not moved.

        Returns:
            str: Base-58 encoded address.
        """
        return self.externalAddresses[self.lastSeenExt+self.cursorExt]
    def privateExtendedKey(self, pw):
        """
        Decode the private extended key for the account using the provided
        SecretKey.

        Args:
            pw (SecretKey): The secret key.

        Returns:
            crypto.ExtendedKey: The current account's decoded private key.
        """
        return crypto.decodeExtendedKey(self.net, pw, self.privKeyEncrypted)
    def publicExtendedKey(self, pw):
        """
        Decode the public extended key for the account using the provided
        SecretKey.

        Args:
            pw (SecretKey): The secret key.

        Returns:
            crypto.ExtendedKey: The current account's decoded public key.
        """
        return crypto.decodeExtendedKey(self.net, pw, self.pubKeyEncrypted)
    def open(self, pw):
        """
        Open the account. While the account is open, the private and public keys
        are stored at least in memory. No precautions are taken to prevent the
        the keys from getting into swap memory, but the ByteArray keys are
        wrappers for mutable Python bytearrays and can be zeroed on close.

        Args:
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

        Returns:
            int: Internal (1) or external (0) branch.
            int: Address index.
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

        Returns:
            secp256k1.PrivateKey: The private key structure for the address.
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
        coinTypeLegacyPubEnc, coinTypeLegacyPrivEnc, coinTypeSLIP0044PubEnc,
        coinTypeSLIP0044PrivEnc, baseAccount, privParams, pubParams):
        """
        Args:
            cryptoKeyPubEnc (ByteArray): Random bytes in an array of length
                crypto.KEY_SIZE used to encrypt the coin type's public key.
            cryptoKeyPrivEnc (ByteArray): Random bytes in an array of length
                crypto.KEY_SIZE used to encrypt the coin type's private key.
            cryptoKeyScriptEnc (ByteArray): Random bytes in an array of length
                crypto.KEY_SIZE used to encrypt scripts.
            coinTypeLegacyPubEnc (ByteArray): The encrypted legacy extended
                public key.
            coinTypeLegacyPrivEnc (ByteArray): The encrypted legacy extended
                private key.
            coinTypeSLIP0044PubEnc (ByteArray): The encrypted SLIP0044 extended
                public key.
            coinTypeSLIP0044PrivEnc (ByteArray): The encrypted SLIP0044 extended
                private key.
            baseAccount (Account): Account derived from the legacy coin type.
            privParams (byte-like): Identifies the network and private key
                status.
            pubParams (byte-like): Identifies the network and public key
                status.
        """
        # The crypto keys are used to decrypt the other keys.
        self.cryptoKeyPubEnc = cryptoKeyPubEnc
        self.cryptoKeyPrivEnc = cryptoKeyPrivEnc
        self.cryptoKeyScriptEnc = cryptoKeyScriptEnc

        # The coin-type keys are used to generate a master key that can be used
        # to generate accounts for any BIP0044 coin.
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

        Returns:
            Account: The account at idx.
        """
        return self.accounts[idx]
    def openAccount(self, acct, pw):
        """
        Open an account.

        Args:
            acct (int): The acccount index, which is its position in the
                accounts list.
            net (obj): Network parameters.
            pw (byte-like): A UTF-8-encoded user-supplied password for the
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
        """
        Get the private extended key for the account at index acct using the
        provided SecretKey.

        Args:
            acct (int): The account's index.
            net (obj): Network parameters. Not used.
            pw (SecretKey): The secret key.

        Returns:
            crypto.ExtendedKey: The account's decoded private key.
        """
        userSecret = crypto.SecretKey.rekey(pw, self.privParams)
        cryptKeyPriv = ByteArray(userSecret.decrypt(self.cryptoKeyPrivEnc.bytes()))
        account = self.accounts[acct]
        return account.privateExtendedKey(cryptKeyPriv)
    def acctPublicKey(self, acct, net, pw):
        """
        Get the public extended key for the account at index acct using the
        provided SecretKey.

        Args:
            acct (int): The account's index.
            net (obj): Network parameters. Not used.
            pw (SecretKey): The secret key.

        Returns:
            crypto.ExtendedKey: The account's decoded public key.
        """
        userSecret = crypto.SecretKey.rekey(pw, self.pubParams)
        cryptKeyPub = ByteArray(userSecret.decrypt(self.cryptoKeyPubEnc.bytes()))
        account = self.accounts[acct]
        return account.publicExtendedKey(cryptKeyPub)

tinyjson.register(AccountManager)


def createNewAccountManager(seed, pubPassphrase, privPassphrase, chainParams, constructor=None):
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

    Returns:
        AccountManager: An initialized account manager.
    """
    constructor = constructor if constructor else Account

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

    # Generate new master keys. These master keys are used to protect the
    # crypto keys that will be generated next.
    masterKeyPub = crypto.SecretKey(pubPassphrase)

    masterKeyPriv = crypto.SecretKey(privPassphrase)

    # Generate new crypto public, private, and script keys. These keys are
    # used to protect the actual public and private data such as addresses,
    # extended keys, and scripts.
    cryptoKeyPub = ByteArray(generateSeed(crypto.KEY_SIZE))

    cryptoKeyPriv = ByteArray(generateSeed(crypto.KEY_SIZE))

    cryptoKeyScript = ByteArray(generateSeed(crypto.KEY_SIZE))

    # Encrypt the crypto keys with the associated master keys.
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

    # Derive the default account from the legacy coin type.
    baseAccount = constructor(acctPubLegacyEnc, acctPrivLegacyEnc,
        DEFAULT_ACCOUNT_NAME, CoinSymbols.decred, chainParams.Name)

    # Save the account row for the 0th account derived from the coin type
    # 42 key.
    zerothAccount = constructor(acctPubSLIP0044Enc, acctPrivSLIP0044Enc,
        DEFAULT_ACCOUNT_NAME, CoinSymbols.decred, chainParams.Name)
    # Open the account.
    zerothAccount.open(cryptoKeyPriv)
    # Create the first payment address.
    zerothAccount.generateGapAddresses()
    # Close the account to zero the key.
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
    '''
    Helper function to convert ECDSA public key bytes to a human readable
    ripemind160 hash for use on the specified network.

    Args:
        b (bytes): Public key bytes.
        net (obj): Network the address will be used on.

    Returns:
        crypto.Address: A pubkey-hash address.
    '''
    return crypto.newAddressPubKeyHash(crypto.hash160(b), net, crypto.STEcdsaSecp256k1).string()

class TestAccounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        '''
        Set up for tests. Arguments are ignored.
        '''
        helpers.prepareLogger("TestTinyCrypto")
        # log.setLevel(0)
    def test_child_neuter(self):
        '''
        Test the ExtendedKey.neuter method.
        '''
        extKey = newMaster(testSeed, nets.mainnet)
        extKey.child(0)
        pub = extKey.neuter()
        self.assertEqual(pub.string(), "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbRqbfTCJ9BUnWPCkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk")
    def test_accounts(self):
        '''
        Test account functionality.
        '''
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
            acct.nextExternalAddress()
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
        '''
        Test extended key derivation.
        '''
        kpriv = newMaster(testSeed, nets.mainnet)
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
        '''
        Test internal branch address derivation.
        '''
        pw = "abc".encode()
        acctManager = createNewAccountManager(testSeed, bytearray(0), pw, nets.mainnet)
        # acct = acctManager.account(0)
        acct = acctManager.openAccount(0, pw)
        for i in range(10):
            acct.nextInternalAddress()
    def test_gap_handling(self):
        internalAddrs = [
            "DskHpgbEb6hqkuHchHhtyojpehFToEtjQSo",
            "Dsm4oCLnLraGDedfU5unareezTNT75kPbRb",
            "DsdN6A9bWhKKJ7PAGdcDLxQrYPKEnjnDv2N",
            "Dsifz8eRHvQrfaPXgHHLMDHZopFJq2pBPU9",
            "DsmmzJiTTmpafdt2xx7LGk8ZW8cdAKe53Zx",
            "DsVB47P4N23PK5C1RyaJdqkQDzVuCDKGQbj",
            "DsouVzScdUUswvtCAv6nxRzi2MeufpWnELD",
            "DsSoquT5SiDPfksgnveLv3r524k1v8RamYm",
            "DsbVDrcfhbdLy4YaSmThmWN47xhxT6FC8XB",
            "DsoSrtGYKruQLbvhA92xeJ6eeuAR1GGJVQA",
        ]

        externalAddrs = [
            "DsmP6rBEou9Qr7jaHnFz8jTfrUxngWqrKBw",
            "DseZQKiWhN3ceBwDJEgGhmwKD3fMbwF4ugf",
            "DsVxujP11N72PJ46wgU9sewptWztYUy3L7o",
            "DsYa4UBo379cRMCTpDLxYVfpMvMNBdAGrGS",
            "DsVSEmQozEnsZ9B3D4Xn4H7kEedDyREgc18",
            "DsifDp8p9mRocNj7XNNhGAsYtfWhccc2cry",
            "DsV78j9aF8NBwegbcpPkHYy9cnPM39jWXZm",
            "DsoLa9Rt1L6qAVT9gSNE5F5XSDLGoppMdwC",
            "DsXojqzUTnyRciPDuCFFoKyvQFd6nQMn7Gb",
            "DsWp4nShu8WxefgoPej1rNv4gfwy5AoULfV",
        ]

        global DefaultGapLimit
        gapLimit = DefaultGapLimit = 5
        pw = "abc".encode()
        am = createNewAccountManager(testSeed, bytearray(0), pw, nets.mainnet)
        account = am.openAccount(0, pw)
        account.gapLimit = gapLimit
        listsAreEqual = lambda a, b: len(a) == len(b) and all(x == y  for x,y in zip(a,b))
        self.assertTrue(listsAreEqual(account.internalAddresses, internalAddrs[:gapLimit]))
        # The external branch starts with the "last seen" at the zeroth address, so
        # has one additional address to start.
        self.assertTrue(listsAreEqual(account.externalAddresses, externalAddrs[:gapLimit+1]))

        account.addTxid(internalAddrs[0], "somerandomtxid")
        newAddrs = account.generateGapAddresses()
        self.assertEqual(len(newAddrs), 1)
        self.assertEqual(newAddrs[0], internalAddrs[5])

        # The zeroth external address is considered "seen", so this should not
        # change anything.
        account.addTxid(externalAddrs[0], "somerandomtxid")
        newAddrs = account.generateGapAddresses()
        self.assertEqual(len(newAddrs), 0)

        # Mark the 1st address as seen.
        account.addTxid(externalAddrs[1], "somerandomtxid")
        newAddrs = account.generateGapAddresses()
        self.assertEqual(len(newAddrs), 1)
        self.assertEqual(externalAddrs[1], account.currentAddress())

        # cursor should be at index 0, last seen 1, max index 6, so calling
        # nextExternalAddress 5 time should put the cursor at index 6, which is
        # the gap limit.
        for i in range(5):
            account.nextExternalAddress()
        self.assertEqual(account.currentAddress(), externalAddrs[6])

        # one more should wrap the cursor back to 1, not zero, so the current
        # address is lastSeenExt(=1) + cursor(=1) = 2
        a1 = account.nextExternalAddress()
        self.assertEqual(account.currentAddress(), externalAddrs[2])
        self.assertEqual(a1, account.currentAddress())

        # Sanity check that internal addresses are wrapping too.
        for i in range(20):
            account.nextInternalAddress()
        addrs = account.internalAddresses
        self.assertEqual(addrs[len(addrs)-1], internalAddrs[5])
