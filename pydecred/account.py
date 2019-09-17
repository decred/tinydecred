"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

The DecredAccount inherits from the tinydecred base Account and adds staking 
support.
"""

from tinydecred.accounts import Account, EXTERNAL_BRANCH
from tinydecred.util import tinyjson, helpers
from tinydecred.crypto.crypto import AddressSecpPubKey

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
                associated with the specified address.
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
            blockchainUTXOs (list(obj)): A list of Python objects decoded from 
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
    def addressesOfInterest(self):
        """
        Overload the base class to add the voting address.
        """
        return self.addTicketAddresses(super().addressesOfInterest())
    def votingKey(self):
        """
        This may change, but for now, the voting key is from the zeroth 
        child of the zeroth child of the external branch.
        """
        return self.privKey.child(EXTERNAL_BRANCH).child(0).child(0).privateKey()
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
            pool (stakepool.StakePool): The stake pool object.
        """
        self.stakePools = [pool] + [p for p in self.stakePools if p.url != pool.url]
    def hasPool(self):
        """
        hasPool will return True if the wallet has at least one pool set.
        """
        return self.stakePool() != None
    def stakePool(self):
        """
        stakePool is the default stakepool.StakePool for the account. 

        Returns:
            staekpool.StakePool: The default stake pool object.
        """
        if self.stakePools:
            return self.stakePools[0]
        return None
    def ticketStats(self):
        """
        A getter for the stakeStats.
        """
        return self.stakeStats
    def sendToAddress(self, value, address, feeRate, blockchain):
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
            internal = self.getChangeAddress,
        )
        tx, spentUTXOs, newUTXOs = blockchain.sendToAddress(value, address, keysource, self.getUTXOs, feeRate)
        self.addMempoolTx(tx)
        self.spendUTXOs(spentUTXOs)
        for utxo in newUTXOs:
            self.addUTXO(utxo)
        return tx
    def purchaseTickets(self, qty, price, blockchain):
        """
        purchaseTickets completes the purchase of the specified tickets. The 
        DecredAccount uses the blockchain to do the heavy lifting, but must 
        prepare the TicketRequest and KeySource and gather some other account-
        related information.
        """
        keysource = KeySource(
            priv = self.getPrivKeyForAddress,
            internal = self.getChangeAddress,
        )
        pool = self.stakePool()
        pi = pool.purchaseInfo
        req = TicketRequest(
            minConf = 0, 
            expiry = 0, 
            spendLimit = int(price*qty*1.1*1e8), # convert to atoms here
            poolAddress = pi.poolAddress, 
            votingAddress = pi.ticketAddress, 
            ticketFee = 0, # use network default
            poolFees = pi.poolFees, 
            count = qty, 
            txFee = 0, # use network default
        )
        txs, spentUTXOs, newUTXOs = blockchain.purchaseTickets(keysource, self.getUTXOs, req)
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
    
tinyjson.register(DecredAccount)