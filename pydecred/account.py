"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

The DecredAccount inherits from the tinydecred base Account and adds staking
support.
"""

from tinydecred.wallet.accounts import Account
from tinydecred.util import tinyjson, helpers
from tinydecred.crypto.crypto import AddressSecpPubKey, CrazyKeyError
from tinydecred.pydecred import txscript
from tinydecred.pydecred.vsp import VotingServiceProvider

log = helpers.getLogger("DCRACCT")

# In addition to the standard internal and external branches, we'll have a third
# branch. This should help accomodate upcoming changes to dcrstakepool. See also
# https://github.com/decred/dcrstakepool/pull/514
STAKE_BRANCH = 2

class KeySource(object):
    """
    Implements the KeySource API from tinydecred.api. Must provide access to
    internal addresses via the KeySource.internal method, and PrivateKeys for a
    specified address via the KeySource.priv method. This implementation just
    sets the passed functions to class properties with the required method
    names.
    """
    def __init__(self, priv, internal):
        """
        Args:
            priv (func): func(address : string) -> PrivateKey. Retrieves the
                private key associated with the specified address.
            internal (func): func() -> address : string. Get a new internal
                address.
        """
        self.priv = priv
        self.internal = internal

class TicketRequest:
    """
    The TicketRequest is required to purchase tickets.
    """
    def __init__(self, minConf, expiry, spendLimit, poolAddress, votingAddress, ticketFee, poolFees, count, txFee):
        # minConf is just a placeholder for now. Account minconf is 0 until
        # I add the ability to change it.
        self.minConf = minConf
        # expiry can be set to some reasonable block height. This may be
        # important when approaching the end of a ticket window.
        self.expiry = expiry
        # Price is calculated purely from the ticket count, price, and fees, but
        # cannot go over spendLimit.
        self.spendLimit = spendLimit
        # The VSP fee payment address.
        self.poolAddress = poolAddress
        # The P2SH voting address based on the 1-of-2 multi-sig script you share
        # with the VSP.
        self.votingAddress = votingAddress
        # ticketFee is the transaction fee rate to pay the miner for the ticket.
        # Set to zero to use wallet's network default fee rate.
        self.ticketFee = ticketFee
        # poolFees are set by the VSP. If you don't set these correctly, the
        # VSP may not vote for you.
        self.poolFees = poolFees
        # How many tickets to buy.
        self.count = count
        # txFee is the transaction fee rate to pay the miner for the split
        # transaction required to fund the ticket.
        # Set to zero to use wallet's network default fee rate.
        self.txFee = txFee


class TicketStats:
    """
    TicketStats is basic information about the account's staking status.
    """
    def __init__(self, count=0, value=0):
        """
        Args:
            count (int): How many tickets the account owns. No differentiation
                is made between immature, live, missed, or expired tickets.
            value (int): How much value is locked in the tickets counted in
                count.
        """
        self.count = count
        self.value = value

class DecredAccount(Account):
    """
    DecredAccount is the Decred version of the base tinydecred Account.
    Decred Account inherits Account, and adds the necessary functionality to
    handle staking.
    """
    def __init__(self, *a, **k):
        """
        All constructor aruments are passed directly to the parent Account.
        """
        super().__init__(*a, *k)
        self.tickets = []
        self.stakeStats = TicketStats()
        self.stakePools = []
        self.blockchain = None
        self.signals = None
        self._votingKey = None
    def __tojson__(self):
        obj = super().__tojson__()
        return helpers.recursiveUpdate(obj, {
            "tickets": self.tickets,
            "stakePools": self.stakePools,
        })
        return obj
    @staticmethod
    def __fromjson__(obj):
        acct = Account.__fromjson__(obj, cls=DecredAccount)
        acct.tickets = obj["tickets"]
        acct.stakePools = obj["stakePools"]
        return acct
    def open(self, pw):
        """
        Open the Decred account. Runs the parent's method, then performs some
        Decred-specific initialization.
        """
        super().open(pw)
        # The voting key is the first non-crazy stake-branch child.
        for i in range(3):
            try:
                self._votingKey = self.privKey.child(STAKE_BRANCH).child(i).privateKey()
                return
            except CrazyKeyError:
                continue
        # It is realistically impossible to reach here.
        raise Exception("error finding voting key")
    def close(self):
        """
        Close the Decred account. Runs the parent's method, then performs some
        Decred-specific clean up.
        """
        super().close()
        self._votingKey.key.zero()
        self._votingKey = None
    def updateStakeStats(self):
        """
        Updates the stake stats object.
        """
        ticketCount = 0
        ticketVal = 0
        for utxo in self.utxos.values():
            if utxo.isTicket():
                ticketCount += 1
                ticketVal += utxo.satoshis
                self.tickets.append(utxo.txid)
        self.stakeStats = TicketStats(ticketCount, ticketVal)

    def resolveUTXOs(self, blockchainUTXOs):
        """
        resolveUTXOs is run once at the end of a sync. Using this opportunity
        to hook into the sync to authorize the stake pool.

        Args:
            blockchainUTXOs (list(object)): A list of Python objects decoded from
                dcrdata's JSON response from ...addr/utxo endpoint.
        """
        super().resolveUTXOs(blockchainUTXOs)
        self.updateStakeStats()
        pool = self.stakePool()
        if pool:
            pool.authorize(self.votingAddress(), self.net)
    def addUTXO(self, utxo):
        """
        Add the UTXO. Update the stake stats if this is a ticket.
        """
        super().addUTXO(utxo)
        if utxo.isTicket():
            self.updateStakeStats()
    def addTicketAddresses(self, a):
        """
        Add the ticket voting addresses from each known stake pool.

        Args:
            a (list(string)): The ticket addresses will be appended to this
                list.
        """
        for pool in self.stakePools:
            if pool.purchaseInfo:
                a.append(pool.purchaseInfo.ticketAddress)
        return a
    def allAddresses(self):
        """
        Overload the base class to add the voting address.
        """
        return self.addTicketAddresses(super().allAddresses())
    def watchAddrs(self):
        """
        Overload the base class to add the voting address.
        """
        return self.addTicketAddresses(super().watchAddrs())
    def votingKey(self):
        """
        For now, the voting key is the zeroth child.
        """
        return self._votingKey
    def votingAddress(self):
        """
        The voting address is the pubkey address (not pubkey-hash) for the
        account. Tinydecred defines this as the zeroth child of the zeroth child
        of the external branch key.

        Returns:
            AddressSecpPubkey: The address object.
        """
        return AddressSecpPubKey(self.votingKey().pub.serializeCompressed(), self.net).string()
    def setPool(self, pool):
        """
        Set the specified pool as the default.

        Args:
            pool (vsp.VotingServiceProvider): The stake pool object.
        """
        assert isinstance(pool, VotingServiceProvider)
        self.stakePools = [pool] + [p for p in self.stakePools if p.apiKey != pool.apiKey]
        bc = self.blockchain
        addr = pool.purchaseInfo.ticketAddress
        for txid in bc.txsForAddr(addr):
            self.addTxid(addr, txid)
        for utxo in bc.UTXOs([addr]):
            self.addUTXO(utxo)
        self.updateStakeStats()
        self.signals.balance(self.calcBalance(self.blockchain.tip["height"]))
    def hasPool(self):
        """
        hasPool will return True if the wallet has at least one pool set.
        """
        return self.stakePool() != None
    def stakePool(self):
        """
        stakePool is the default vsp.VotingServiceProvider for the
        account.

        Returns:
            vsp.VotingServiceProvider: The default stake pool object.
        """
        if self.stakePools:
            return self.stakePools[0]
        return None
    def ticketStats(self):
        """
        A getter for the stakeStats.

        Returns:
            TicketStats: The staking stats.
        """
        return self.stakeStats
    def blockSignal(self, sig):
        """
        Process a new block from the explorer.

        Arg:
            sig (obj or string): The block explorer's json-decoded block
                notification.
        """
        block = sig["message"]["block"]
        for newTx in block["Tx"]:
            txid = newTx["TxID"]
            # only grab the tx if its a transaction we care about.
            if self.caresAboutTxid(txid):
                tx = self.blockchain.tx(txid)
                self.confirmTx(tx, self.blockchain.tipHeight)
        # "Spendable" balance can change as utxo's mature, so update the
        # balance at every block.
        self.signals.balance(self.calcBalance(self.blockchain.tipHeight))
    def addressSignal(self, addr, txid):
        """
        Process an address notification from the block explorer.

        Args:
            addr (obj or string): The block explorer's json-decoded address
                notification's address.
            txid (obj or string): The block explorer's json-decoded address
                notification's txid.
        """
        tx = self.blockchain.tx(txid)
        self.addTxid(addr, tx.txid())

        matches = False
        # scan the inputs for any spends.
        for txin in tx.txIn:
            op = txin.previousOutPoint
            # spendTxidVout is a no-op if output is unknown
            match = self.spendTxidVout(op.txid(), op.index)
            if match:
                matches += 1
        # scan the outputs for any new UTXOs
        for vout, txout in enumerate(tx.txOut):
            try:
                _, addresses, _ = txscript.extractPkScriptAddrs(0, txout.pkScript, self.net)
            except Exception:
                # log.debug("unsupported script %s" % txout.pkScript.hex())
                continue
            # convert the Address objects to strings.
            if addr in (a.string() for a in addresses):
                utxo = self.blockchain.txVout(txid, vout)
                utxo.address = addr
                self.addUTXO(utxo)
                matches += 1
        if matches:
            # signal the balance update
            self.signals.balance(self.calcBalance(self.blockchain.tip["height"]))
    def sendToAddress(self, value, address, feeRate):
        """
        Send the value to the address.

        Args:
            value int: The amount to send, in atoms.
            address str: The base-58 encoded pubkey hash.

        Returns:
            MsgTx: The newly created transaction on success, `False` on failure.
        """
        keysource = KeySource(
            priv = self.getPrivKeyForAddress,
            internal = self.nextInternalAddress,
        )
        tx, spentUTXOs, newUTXOs = self.blockchain.sendToAddress(value, address, keysource, self.getUTXOs, feeRate)
        self.addMempoolTx(tx)
        self.spendUTXOs(spentUTXOs)
        for utxo in newUTXOs:
            self.addUTXO(utxo)
        return tx
    def purchaseTickets(self, qty, price):
        """
        purchaseTickets completes the purchase of the specified tickets. The
        DecredAccount uses the blockchain to do the heavy lifting, but must
        prepare the TicketRequest and KeySource and gather some other account-
        related information.
        """
        keysource = KeySource(
            priv = self.getPrivKeyForAddress,
            internal = self.nextInternalAddress,
        )
        pool = self.stakePool()
        pi = pool.purchaseInfo
        req = TicketRequest(
            minConf = 0,
            expiry = 0,
            spendLimit = int(round(price*qty*1.1*1e8)), # convert to atoms here
            poolAddress = pi.poolAddress,
            votingAddress = pi.ticketAddress,
            ticketFee = 0, # use network default
            poolFees = pi.poolFees,
            count = qty,
            txFee = 0, # use network default
        )
        txs, spentUTXOs, newUTXOs = self.blockchain.purchaseTickets(keysource, self.getUTXOs, req)
        if txs:
            # Add the split transactions
            self.addMempoolTx(txs[0])
            # Add all tickets
            for tx in txs[1]:
                self.addMempoolTx(tx)
        # Store the txids.
        self.tickets.extend([tx.txid() for tx in txs[1]])
        # Remove spent utxos from cache.
        self.spendUTXOs(spentUTXOs)
        # Add new UTXOs to set. These may be replaced with network-sourced
        # UTXOs once the wallet receives an update from the BlockChain.
        for utxo in newUTXOs:
            self.addUTXO(utxo)
        return txs[1]
    def sync(self, blockchain, signals):
        """
        Synchronize the UTXO set with the server. This should be the first
        action after the account is opened or changed.
        """
        self.blockchain = blockchain
        self.signals = signals
        signals.balance(self.balance)
        self.generateGapAddresses()

        # First, look at addresses that have been generated but not seen. Run in
        # loop until the gap limit is reached.
        requestedTxs = 0
        addrs = self.unseenAddrs()
        while addrs:
            for addr in addrs:
                for txid in blockchain.txsForAddr(addr):
                    requestedTxs += 1
                    self.addTxid(addr, txid)
            addrs = self.generateGapAddresses()
        log.debug("%d address transactions sets fetched" % requestedTxs)

        # start with a search for all known addresses
        addresses = self.allAddresses()

        # Until the server stops returning UTXOs, keep requesting more addresses
        # to check.
        while True:
            # Update the account with known UTXOs.
            blockchainUTXOs = blockchain.UTXOs(addresses)
            if not blockchainUTXOs:
                break
            self.resolveUTXOs(blockchainUTXOs)
            addresses = self.generateGapAddresses()
            if not addresses:
                break

        # Subscribe to block and address updates.
        blockchain.addressReceiver = self.addressSignal
        blockchain.subscribeBlocks(self.blockSignal)
        watchAddresses = self.watchAddrs()
        if watchAddresses:
            blockchain.subscribeAddresses(watchAddresses)
        # Signal the new balance.
        signals.balance(self.calcBalance(self.blockchain.tip["height"]))

        return True

tinyjson.register(DecredAccount, "DecredAccount")