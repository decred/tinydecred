"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""
import os
import unittest
from threading import Lock as Mutex
from tinydecred.util import tinyjson, helpers
from tinydecred.crypto import crypto, mnemonic
from tinydecred.pydecred import txscript
from tinydecred.accounts import createNewAccountManager

log = helpers.getLogger("WLLT") # , logLvl=0)

VERSION = "0.0.1"

class KeySource(object):
    """
    Implements the KeySource API from tinydecred.api.
    """
    def __init__(self, priv, internal):
        self.priv = priv
        self.internal = internal

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
        self.selectedAccount = None
        self.openAccount = None
        # The fileKey is a hash generated with the user's password as an input.
        # The fileKey hash is used to AES encrypt and decrypt the wallet file.
        self.fileKey = None
        # An object implementing the BlockChain API. Eventually should be moved
        # from wallet in favor of a common interface that wraps a full, spv, or
        # light node.
        self.blockchain = None
        # The best block.
        self.users = 0
        # User provided callbacks for certain events.
        self.signals = None
        self.mtx = Mutex()
        self.version = None
    def __tojson__(self):
        return {
            "acctManager": self.acctManager,
            "version": self.version,
        }
    @staticmethod
    def __fromjson__(obj):
        w = Wallet()
        w.acctManager = obj["acctManager"]
        w.version = obj["version"]
        return w
    @staticmethod
    def create(path, password, chain, userSeed = None):
        """
        Create a wallet, locked by `password`, for the network indicated by
        `chain`. The seed will be randomly generated, unless a `userSeed` is
        provided.

        Args:
            path (str): Filepath to store wallet.
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
        wallet = Wallet()
        wallet.version = VERSION
        wallet.path = path
        seed = userSeed.bytes() if userSeed else crypto.generateSeed(crypto.KEY_SIZE)
        pw = password.encode()
        # Create the keys and coin type account, using the seed, the public
        # password, private password and blockchain params.
        wallet.acctManager = createNewAccountManager(seed, b'', pw, chain)
        wallet.fileKey = crypto.SecretKey(pw)
        wallet.selectedAccount = wallet.acctManager.openAccount(0, password)
        wallet.close()

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
        decoded = mnemonic.decode(words)
        cksum = decoded[-1]
        userSeed = decoded[:-1]
        cs = crypto.sha256ChecksumByte(userSeed.b)
        if cs != cksum:
            raise Exception("bad checksum %r != %r" % (cs, cksum))
        return Wallet.create(path, password, chain, userSeed=userSeed)
    def save(self):
        """
        Save the encrypted wallet.
        """
        if not self.fileKey:
            log.error("attempted to save a closed wallet")
            return
        encrypted = self.fileKey.encrypt(tinyjson.dump(self).encode()).hex()
        w = tinyjson.dump({
            "keyparams": self.fileKey.params(),
            "wallet": encrypted,
        })
        helpers.saveFile(self.path, w)
    def setAccountHandlers(self, blockchain, signals):
        """
        Set blockchain params and user defined callbacks for accounts.

        Args:
            blockchain (obj): An api.Blockchain for accounts.
            signals (obj): An api.Signals.
        """
        self.blockchain = blockchain
        self.signals = signals
    @staticmethod
    def openFile(path, password):
        """
        Open the wallet located at `path`, encrypted with `password`. The zeroth
        account or the wallet is open, but the wallet's `blockchain` and
        `signals` are not set.

        Args:
            path (str): Filepath of the encrypted wallet.
            password (str): User-supplied password. Must match password in use
                when saved.

        Returns:
            Wallet: An opened, unlocked Wallet with the default account open.
        """
        if not os.path.isfile(path):
            raise FileNotFoundError("no wallet found at %s" % path)
        with open(path, 'r') as f:
            wrapper = tinyjson.load(f.read())
        pw = password.encode()
        keyParams = wrapper["keyparams"]
        fileKey = crypto.SecretKey.rekey(pw, keyParams)
        wallet = tinyjson.load(fileKey.decrypt(bytes.fromhex(wrapper["wallet"])).decode())
        wallet.path = path
        wallet.fileKey = fileKey
        wallet.selectedAccount = wallet.acctManager.openAccount(0, password)
        wallet.close()
        return wallet
    def open(self, acct, password, blockchain, signals):
        """
        Open an account. The Wallet is returned so that it can be used in
            `with ... as` block for context management.

        Args:
            acct (int): The account number to open.
            password (str): Wallet password. Should be the same as used to open
                the wallet.
            blockchain (obj): An api.Blockchain for the account.
            signals (obj): An api.Signals.

        Returns:
            Wallet: The wallet with the default account open.
        """
        self.setAccountHandlers(blockchain, signals)
        self.selectedAccount = self.openAccount = self.acctManager.openAccount(acct, password)
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
            acct (int): The index of the account. A new wallet has a single
                Decred account located at index 0.

        Returns:
            Account: The Account object at index acct.
        """
        aMgr = self.acctManager
        if len(aMgr.accounts) <= acct:
            raise Exception("requested unknown account number %i" % acct)
        return aMgr.account(acct)
    def getNewAddress(self):
        """
        Get the next unused external address.

        Returns:
            str: The next unused external address.
        """
        a = self.selectedAccount.getNextPaymentAddress()
        if self.blockchain:
            self.blockchain.subscribeAddresses(a)
        self.save()
        return a
    def paymentAddress(self):
        """
        Gets the payment address at the cursor.

        Returns:
            str: The current external address.
        """
        return self.selectedAccount.paymentAddress()
    def balance(self):
        """
        Get the balance of the currently selected account.

        Returns:
            Balance: The current account's Balance object.
        """
        return self.selectedAccount.balance
    def getUTXOs(self, requested, approve=None):
        """
        Find confirmed and mature UTXOs, smallest first, that sum to the
        requested amount, in atoms.

        Args:
            requested (int): Required amount in atoms.
            filter (func(UTXO) -> bool): Optional UTXO filtering function.

        Returns:
            list(UTXO): A list of UTXOs.
            bool: True if the UTXO sum is >= the requested amount.
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
        Get the private key for the provided address.

        Args:
            addr (str): The base-58 encoded address.

        Returns:
            secp256k1.PrivateKey: The private key structure for the address.
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
        acct = self.selectedAccount
        for newTx in block["Tx"]:
            txid = newTx["TxID"]
            # Only grab the tx if it's a transaction we care about.
            if acct.caresAboutTxid(txid):
                tx = self.blockchain.tx(txid)
                acct.confirmTx(tx, self.blockchain.tipHeight)
        # "Spendable" balance can change as UTXOs mature, so update the
        # balance at every block.
        self.signals.balance(acct.calcBalance(self.blockchain.tipHeight))
    def addressSignal(self, addr, txid):
        """
        Process an address notification from the block explorer.

        Args:
            addr (obj or string): The block explorer's json-decoded address
                notification's address.
            txid (obj or string): The block explorer's json-decoded address
                notification's txid.
        """
        acct = self.selectedAccount

        tx = self.blockchain.tx(txid)
        acct.addTxid(addr, tx.txid())

        matches = False
        # Scan the inputs for any spends.
        for txin in tx.txIn:
            op = txin.previousOutPoint
            # spendTxidVout is a no-op if output is unknown.
            match = acct.spendTxidVout(op.txid(), op.index)
            if match:
                matches += 1
        # Scan the outputs for any new UTXOs.
        for vout, txout in enumerate(tx.txOut):
            try:
                _, addresses, _ = txscript.extractPkScriptAddrs(0, txout.pkScript, acct.net)
            except Exception:
                # log.debug("unsupported script %s" % txout.pkScript.hex())
                continue
            # Convert the Address objects to strings.
            if addr in (a.string() for a in addresses):
                log.debug("found new utxo for %s" % addr)
                utxo = self.blockchain.txVout(txid, vout)
                utxo.address = addr
                acct.addUTXO(utxo)
                matches += 1
        if matches:
            # Signal the balance update.
            self.signals.balance(acct.calcBalance(self.blockchain.tip["height"]))
    def sync(self):
        """
        Synchronize the UTXO set with the server. This should be the first
        action after the account is opened or changed.

        Returns:
            bool: `True` if no exceptions were encountered.
        """
        acctManager = self.acctManager
        acct = acctManager.account(0)
        gapPolicy = 5
        acct.generateGapAddresses(gapPolicy)
        watchAddresses = set()

        # Send the initial balance.
        self.signals.balance(acct.balance)
        addresses = acct.allAddresses()

        # Update the account with known UTXOs.
        chain = self.blockchain
        blockchainUTXOs = chain.UTXOs(addresses)
        acct.resolveUTXOs(blockchainUTXOs)

        # Subscribe to block and address updates.
        chain.subscribeBlocks(self.blockSignal)
        watchAddresses = acct.addressesOfInterest()
        if watchAddresses:
            chain.subscribeAddresses(watchAddresses, self.addressSignal)
        # Signal the new balance.
        b = acct.calcBalance(self.blockchain.tip["height"])
        self.signals.balance(b)
        self.save()
        return True
    def sendToAddress(self, value, address, feeRate=None):
        """
        Send the value to the address.

        Args:
            value (int): The amount to send, in atoms.
            address (str): The base-58 encoded pubkey hash.

        Returns:
            MsgTx or bool: The newly created transaction on success, `False` on
                failure.
        """
        acct = self.openAccount
        keysource = KeySource(
            priv = self.getKey,
            internal = acct.getChangeAddress,
        )
        tx, spentUTXOs, newUTXOs = self.blockchain.sendToAddress(value, address, keysource, self.getUTXOs, feeRate)
        acct.addMempoolTx(tx)
        acct.spendUTXOs(spentUTXOs)
        for utxo in newUTXOs:
            acct.addUTXO(utxo)
        self.signals.balance(acct.calcBalance(self.blockchain.tip["height"]))
        self.save()
        return tx

tinyjson.register(Wallet)


class TestWallet(unittest.TestCase):
    def test_tx_to_outputs(self):
        pass
