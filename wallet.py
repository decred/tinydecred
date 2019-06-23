"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details
"""
import os
import unittest
import time
from threading import Lock as Mutex
from tinydecred.util import tinyjson, helpers
from tinydecred.crypto import crypto, mnemonic, rando
from tinydecred.pydecred import txscript
from tinydecred.accounts import createNewAccountManager, UTXO
from tinydecred.crypto.bytearray import ByteArray

log = helpers.getLogger("WLLT", logLvl=0)

ID_TAG = "tinywallet"
VERSION = "0.0.1"

SALT_SIZE = 32

def generateSalt(self):
    """
    Generate a random salt.

    Returns:
        ByteArray: Random bytes.
    """
    return ByteArray(rando.generateSeed(SALT_SIZE))

class KeySource:
    """
    Implements the KeySource API from tinydecred.api.
    """
    def __init__(self, priv, change):
        self.priv = priv
        self.change = change

class Wallet:
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
        with wallet.open(pw) as w:
            w.sendToAddress(v, addr, sender)
        ```
    If the wallet is used in this way, the mutex will be locked and unlocked
    appropriately.
    """
    def __init__(self):
        """
        Args:
            chain (obj): Network parameters to associate with the wallet. Should 
                probably move this to the account level. 
        """
        # The path to the filesystem location of the encrypted wallet file. 
        self.path = None
        # The AccountManager that holds all account information. acctManager is 
        # saved with the encrypted wallet file.
        self.acctManager = None
        self.openAccount = None
        # The fileKey is a hash generated with the user's password as an input. 
        # The fileKey hash is used to AES encrypt and decrypt the wallet file.
        self.fileKey = None
        # An object implementing the BlockChain API. Eventually should be move 
        # from wallet in favor of a common interface that wraps a full, spv, or 
        # light node.
        self.blockchain = None
        # The best block.
        self.tip = None
        self.users = 0
        # A user provided callbacks for certain events.
        self.signals = None
        self.mtx = Mutex()
        self.salt = None
    def __tojson__(self):
        return {
            "acctManager": self.acctManager,
            "chainName": self.chainName,
        }
    @staticmethod
    def __fromjson__(obj):
        w = Wallet(None)
        w.chainName = obj["chainName"]
        w.acctManager = obj["acctManager"]
        return w
    @staticmethod
    def create(path, password, chain, userSeed = None):
        """
        Create a wallet, locked by `password`, for the network indicated by 
        `chain`. The seed will be randomly generated, unless a `userSeed` is 
        provided. 

        Args:
            password (str): User provided password. The password will be used to 
                both decrypt the wallet, and unlock any accounts created.
            chain (obj): Network parameters for the zeroth account ExtendedKey.
            userSeed (ByteArray): A seed for wallet generate, likely generated 
                from a mnemonic seed word list.

        Returns: 
            Wallet: An initialized wallet with a single Decred account. 
            list(str): A mnemonic seed. Only retured when the caller does not 
                provide a seed. 
        """
        if os.path.isfile(path):
            raise FileExistsError("wallet already exists at path %s" % path)
        wallet = Wallet(chain)
        wallet.path = path
        seed = userSeed.bytes() if userSeed else crypto.generateSeed(crypto.KEY_SIZE)
        pw = password.encode("ascii")
        # Create the keys and coin type account, using the seed, the public password, private password and blockchain params.
        wallet.acctManager = createNewAccountManager(seed, ''.encode(), pw, chain)
        wallet.file = {
            "tag": ID_TAG,
            "accounts": wallet.acctManager,
            "version": VERSION,
        }
        wallet.salt = generateSalt()

        wallet.fileKey = crypto.hash160(pw+wallet.salt.bytes())
        wallet.openAccount = wallet.acctManager.openAccount(0, chain, password.encode("ascii"))
        wallet.save()

        if userSeed:
            # No mnemonic seed is retured when the user provided the seed.
            userSeed.zero()
            return wallet
        words = mnemonic.encode(seed)
        return words, wallet
    @staticmethod
    def createFromMnemonic(words, path, password, chain):
        """
        Creates the wallet from the mnemonic seed.

        Args:
            words (list(str)): mnemonic seed. Assumed to be PGP words.
            password (str): User password. Passed to Wallet.create.
            chain (obj): Network parameters.

        Returns:
            Wallet: A wallet initialized from the seed parsed from `words`.
        """
        userSeed = mnemonic.decode(words)
        return Wallet.create(path, password, chain, userSeed=userSeed)
    def save(self):
        """
        Save the encrypted wallet.
        """
        if not self.fileKey:
            log.error("attempted to save a closed wallet")
            return
        encrypted = crypto.AES.encrypt(self.fileKey.bytes(), tinyjson.dump(self))
        w = tinyjson.dump({
            "salt": self.salt.hex(),
            "wallet": encrypted,
        })
        helpers.saveFile(self.path, w)
    def setAccountHandlers(self, blockchain, signals):
        self.blockchain = blockchain
        self.chain = blockchain.params
        self.chainName = self.chain.Name
        self.signals = signals
    @staticmethod
    def openFile(path, password, chain):
        """
        Open the wallet located at `path`, encrypted with `password`. The zeroth
        account or the wallet is open , but the wallet's `blockchain` and 
        `signals` are not set. 

        Args: 
            path (str): Filepath of the encrypted wallet.
            password (str): User-supplied password. Must match password in use 
                when saved.
            chain (obj): Network parameters.

        Returns:
            Wallet: An opened, unlocked Wallet with the default account open.
        """
        if not os.path.isfile(path):
            raise FileNotFoundError("no wallet found at %s" % path)
        with open(path, 'r') as f:
            wrapper = f.read()
        pw = password.encode("ascii")
        salt = ByteArray(wrapper["salt"])
        fileKey = crypto.hash160(pw+salt.bytes())
        wallet = tinyjson.load(crypto.AES.decrypt(fileKey.bytes(), wrapper["wallet"]))
        wallet.salt = salt
        if wallet.file["tag"] != ID_TAG:
            raise IOError("unable to open wallet with provided password")
        if wallet.chainName != wallet.chainName:
            raise Exception("wrong chain")
        wallet.path = path
        wallet.fileKey = fileKey
        wallet.openAccount = wallet.acctManager.openAccount(0, chain, pw)
        wallet.save()
        return wallet
    def open(self, password, blockchain, signals):
        """
        Open an account. The Wallet is returned so that it can be used in 
            `with ... as` block for context management. 

        Args:
            password (str): Wallet password. Should be the same as used to open the 
                wallet. 

        Returns: 
            Wallet: The wallet with the default account open.
        """
        # self.fileKey = crypto.hash160(pw+self.salt.bytes())
        self.setAccountHandlers(blockchain, signals)
        self.openAccount = self.acctManager.openAccount(0, self.chain, password)
        return self
    def lock(self):
        """
        Lock the wallet for use. The preferred way to lock and unlock the wallet
        is indirectly through a contextual contextual `with ... as` block. 
        """
        self.mtx.acquire()
    def unlock(self):
        """
        Unlock the wallet for use. The preferred way to lock and unlock the 
        wallet is indirectly through a contextual contextual `with ... as` block. 
        """
        self.mtx.release()
    def __enter__(self):
        """
        For use in a `with ... as` block, the returned value is assigned to the 
        `as` variable. 
        """
        # The user count must be incremented before locking. In python, simple
        # I Python, simple assignment is thead-safe, but compound assignment, 
        # e.g. += is not. 
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
        if self.users == 0:
            self.close()
    def close(self):
        """
        Save the wallet and close any open account. 
        """
        self.save()
        # self.fileKey = None
        if self.openAccount:
            self.openAccount.close()
            self.openAccount = None
    def account(self, acct):
        """
        Open the account at index `acct`.

        Args:
            acct int: The index of the account. A new wallet has a single Decred
                account located at index 0.
        """
        aMgr = self.acctManager
        if len(aMgr.accounts) <= acct:
            raise Exception("requested unknown account number %i" % acct)
        return aMgr.account(acct)
    def getNewAddress(self):
        """
        Get the next unused external address.
        """
        return self.openAccount.getNextPaymentAddress()
    def paymentAddress(self):
        """
        Gets the payment address at the cursor.
        """
        return self.openAccount.paymentAddress()
    def balance(self):
        """
        Get the balance of the currently selected account.
        """
        if self.openAccount:
            return self.openAccount.balance
        return self.account(0).balance
    def getUTXOs(self, requested, approve=None):
        """
        Find confirmed and mature UTXOs, smallest first, that sum to the 
        requested amount, in atoms. 

        Args:
            requested int: Required amount. Atoms. 
            filter func(UTXO) -> bool: Optional UTXO filtering function.

        Returns: 
            list(UTXO): A list of UTXOs.
            bool: Success. True if the UTXO sum is >= the requested amount. 
        """
        matches = []
        acct = self.openAccount
        collected = 0
        pairs = [(u.satoshis, u) for u in acct.utxoscan()]
        for v, utxo in sorted(pairs, key=lambda p: p[0]):
            if approve and not approve(utxo):
                continue
            matches.append(utxo)
            collected += v
            if collected >= requested:
                break
        return matches, collected >= requested
    def getKey(self, addr):
        """
        Get the PrivateKey for the provided address.

        Args: 
            addr (str): The base-58 encoded address.

        Returns:
            PrivateKey: The private key structure for the address.
        """
        return self.openAccount.getPrivKeyForAddress(addr)
    def blockSignal(self, sig):
        """
        Process a new block from the explorer. 

        Arg:
            sig (obj or string): The block explorer's json-decoded block
            notification.
        """
        block = sig["message"]["block"]
        self.tip = block
        acct = self.openAccount
        for newTx in block["Tx"]:
            txid = newTx["TxID"]
            # only grab the tx if its a transaction we care about.
            if acct.caresAboutTxid(txid):
                tx, _ = self.blockchain.tx(txid)
                acct.confirmTx(tx, block["height"])
    def addressSignal(self, sig):
        """
        Process an address notification from the block explorer.

        Arg:
            sig (obj or string): The block explorer's json-decoded address
            notification.
        """
        print("--processing address signal 1")
        acct = self.openAccount
        txid = sig["message"]["transaction"]
        tx, _ = self.blockchain.tx(txid)
        decodedTx = self.blockchain.getDecodedTx(txid)
        block = decodedTx["block"] if "block" in decodedTx else {}
        blockHeight = block["blockheight"] if "blockheight" in block else -1
        blockTime = block["blocktime"] if "blocktime" in block else time.time()
        addr = sig["message"]["address"]
        acct.addTx(addr, txid)
        matches = False
        print("--processing address signal 2")
        # scan the inputs for any spends.
        for txin in tx.txIn:
            op = txin.previousOutPoint
            match = acct.spendTxidVout(op.hashString(), op.index)
            if match:
                matches += 1
        print("--processing address signal 3")
        # scan the outputs for any new UTXOs
        for vout, txout in enumerate(tx.txOut):
            try:
                _, addresses, _ = txscript.extractPkScriptAddrs(0, txout.pkScript, self.chain)
            except Exception:
                log.debug("unsupported script %s" % txout.pkScript.hex())
                continue
            # convert the Address objects to strings.
            addrs = [a.string() for a in addresses]
            if addr in addrs:
                log.debug("found new utxo for %s" % addr)
                acct.addUTXO(UTXO(
                    address = addr,
                    txid = txid,
                    vout = vout,
                    ts = blockTime,
                    scriptPubKey = txout.pkScript,
                    height = blockHeight,
                    amount = round(txout.value*1e-8),
                    satoshis = txout.value,
                    maturity = blockHeight + self.chain.CoinbaseMaturity if tx.looksLikeCoinbase() else None,
                ))
                matches += 1
        print("--processing address signal 4")
        if matches:
            # signal the balance update
            self.signals.balance(acct.calcBalance(self.tip["height"]))
        print("--done processing address signal 5")
    def sync(self, blockchain, signals):
        """
        Synchronize the UTXO set with the server. This should be the first
        action after the account is opened or changed.
        """
        self.setAccountHandlers(blockchain, signals)
        acctManager = self.acctManager
        acct = acctManager.account(0)
        gapPolicy = 5
        acct.generateGapAddresses(gapPolicy)
        watchAddresses = set()
        blockchain = self.blockchain

        # send the initial balance
        self.signals.balance(acct.balance)
        addresses = acct.allAddresses()
        blockchainUTXOs = blockchain.UTXOs(addresses)
        # addrCount = len(addresses)
        # addrsPerRequest = 20 # dcrdata allows 25        
        # getUTXOs = lambda addrs: blockchain.insight.api.addr.utxo(",".join(addrs))
        # for i in range(addrCount//addrsPerRequest+1):
        #     start = i*addrsPerRequest
        #     end = start + addrsPerRequest
        #     addrs = addresses[start:end]
        #     blockchainUTXOs += [UTXO.parse(u) for u in getUTXOs(addrs)]
        newUTXOs = {}
        dupes = {}
        missingUtxos = []
        for utxo in blockchainUTXOs:
            # If the UTXO is already known, add it to the dupes dict, otherwise
            # process it as new and add it the the newUTXOs dict. 
            if acct.getUTXO(utxo.txid, utxo.vout):
                dupes[utxo.key()] = utxo
            else:
                print("--found new utxo for %s" % utxo.address)
                newUTXOs[utxo.key()] = utxo
        # Check to see if there are any utxos that were previously known, but 
        # not seen anymore.
        for utxo in acct.utxoscan():
            if utxo.key() in dupes:
                missingUtxos.append(utxo)
        # If there are missing UTXOs, remove them. For now, they are simply
        # forgotten, but maybe they should be stored or some checks performed.
        for utxo in missingUtxos:
            acct.removeUTXO(utxo)
        # Add the new UTXOs.
        for utxo in newUTXOs.values():
            acct.addUTXO(utxo)
        # Subscribe to block and address updates.
        blockchain.subscribeBlocks(self.blockSignal)
        watchAddresses = acct.addressesOfInterest()
        if watchAddresses:
            blockchain.subscribeAddresses(watchAddresses, self.addressSignal)
        # Signal the new balance.
        self.signals.balance(acct.calcBalance(self.tip["height"]))
        return True
    def sendToAddress(self, value, address):
        """
        Send the value to the address. 

        Args:
            value int: The amount to send, in atoms.
            address str: The base-58 encoded pubkey hash.

        Returns: 
            MsgTx: The newly created transaction on success, `False` on failure.
        """
        acct = self.openAccount
        keysource = KeySource(
            priv = self.getKey,
            change = acct.getChangeAddress,
        )
        tx, spentUTXOs, newUTXOs = self.blockchain.sendToAddress(value, address, keysource, self.getUTXOs)
        acct.addMempoolTx(tx)
        acct.spendUTXOs(spentUTXOs)
        for utxo in newUTXOs:
            acct.addUTXO(utxo)
        self.signals.balance(acct.calcBalance(self.tip["height"]))
        return self.blockchain.sendToAddress(value, address)
        
tinyjson.register(Wallet)


class TestWallet(unittest.TestCase):
    def test_tx_to_outputs(self):
        pass