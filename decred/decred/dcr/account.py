"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details
"""

from decred.crypto import crypto, opcode
from decred.util import encode, helpers

from . import nets, txscript
from .vsp import VotingServiceProvider


log = helpers.getLogger("DCRACCT")

ByteArray = encode.ByteArray
BuildyBytes = encode.BuildyBytes

# In addition to the standard internal and external branches, we'll have a third
# branch. This should help accomodate upcoming changes to dcrstakepool. See also
# https://github.com/decred/dcrstakepool/pull/514
STAKE_BRANCH = 2

EXTERNAL_BRANCH = 0
INTERNAL_BRANCH = 1

BIPID = 42


class MetaKeys:
    """Keys for the account meta table."""

    vsp = "vsp".encode()


# See CrazyKeyError docs. When an out-of-range key is created, a placeholder
# is set for that child's position internally in Account.
CrazyAddress = "CRAZYADDRESS"

# DefaultGapLimit is the default unused address gap limit defined by BIP0044.
DefaultGapLimit = 20


def filterCrazyAddress(addrs):
    """
    When addresses are read out in bulk, they should be filtered for the
    CrazyAddress.

    Args:
        addrs (list(str)): The addresses to filter.

    Returns:
        list(str): The filtered addresses.
    """
    return [a for a in addrs if a != CrazyAddress]


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

    def __init__(
        self,
        minConf,
        expiry,
        spendLimit,
        poolAddress,
        votingAddress,
        ticketFee,
        poolFees,
        count,
        txFee,
    ):
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


class TinyBlock(object):
    """
    TinyBlock is a block hash and height that satisfies encode.Blobber.
    """

    def __init__(self, blockHash, height):
        """
        Constructor for a TinyBlock

        Args:
            blockHash (ByteArray): The block hash.
            height (int): The block height.
        """
        self.hash = blockHash
        self.height = height

    @staticmethod
    def blob(blk):
        """Satisfies the encode.Blobber API"""
        return BuildyBytes(0).addData(blk.hash).addData(blk.height).b

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("unsupported version")
        if len(d) != 2:
            raise AssertionError("wrong number of pushes. expected 2, got %d" % len(d))
        return TinyBlock(d[0], encode.intFromBytes(d[1]))

    def serialize(self):
        """
        Serialize the TinyBlock.

        Returns:
            ByteArray: The serialized TinyBlock.
        """
        return ByteArray(TinyBlock.blob(self))

    @staticmethod
    def parse(obj):
        """
        Parse the Python dict to a TinyBlock. The dict should have two keys,
        "hash" -> string, and "height" -> number (int)

        Args:
            obj (dict): The block dict.

        Returns:
            TinyBlock: The parsed TinyBlock.
        """
        return TinyBlock(reversed(ByteArray(obj["hash"])), obj["height"])

    def __eq__(self, blk):
        """
        Implements the == operator.

        Args:
            blk (TinyBlock): The block to compare.

        Returns:
            bool: True if they have the same hash and height.
        """
        return self.hash == blk.hash and self.height == blk.height


class TicketInfo(object):
    """
    Ticket-related transaction information.
    """

    def __init__(
        self,
        status,
        purchaseBlock,
        maturityHeight,
        expirationHeight,
        lotteryBlock,
        vote,
        revocation,
    ):
        """
        Ticket information.

        Args:
            status (str): The ticket status. "immature", "live", "expired", etc.
            purchaseBlock (TinyBlock): The ticket purchase block.
            maturityHeight: (int): The height at which the ticket goes live.
            expirationHeight (int): The height at which the ticket expires.
            lotteryBlock (TinyBlock or None): Once chosen, the block in which
                the ticket was selected.
            vote (ByteArray or None): The transaction hash of the vote, if
                the ticket was spent in a vote.
            revocation (ByteArray or None): The transaction hash of the
                revocation, if the ticket was spent in a revocation.
        """
        self.status = status
        self.purchaseBlock = purchaseBlock
        self.maturityHeight = maturityHeight
        self.expirationHeight = expirationHeight
        self.lotteryBlock = lotteryBlock
        self.vote = vote
        self.revocation = revocation

    @staticmethod
    def parse(obj):
        """
        Parse the TicketInfo from the decoded API response.

        Args:
            obj (object): The Python object decoded from the JSON API response.
        """
        ba = lambda b: reversed(ByteArray(b))
        return TicketInfo(
            status=obj["status"],
            purchaseBlock=TinyBlock.parse(obj["purchase_block"]),
            maturityHeight=obj["maturity_height"],
            expirationHeight=obj["expiration_height"],
            lotteryBlock=TinyBlock.parse(obj["lottery_block"]),
            vote=ba(obj["vote"]) if obj["vote"] else None,
            revocation=ba(obj["revocation"]) if obj["revocation"] else None,
        )

    @staticmethod
    def blob(utxo):
        """Satisfies the encode.Blobber API"""
        f = encode.filterNone
        return (
            BuildyBytes(0)
            .addData(utxo.status.encode("utf-8"))
            .addData(
                f(TinyBlock.blob(utxo.purchaseBlock) if utxo.purchaseBlock else None)
            )
            .addData(utxo.maturityHeight)
            .addData(utxo.expirationHeight)
            .addData(
                f(TinyBlock.blob(utxo.lotteryBlock) if utxo.lotteryBlock else None)
            )
            .addData(f(utxo.vote))
            .addData(f(utxo.revocation))
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("invalid TicketInfo version %d" % ver)
        if len(d) != 7:
            raise AssertionError(
                "wrong number of pushes for TicketInfo. wanted 7, got %d" % len(d)
            )

        iFunc = encode.intFromBytes
        f = encode.extractNone

        pbb = f(d[1])
        purchaseBlock = TinyBlock.unblob(pbb) if pbb else None

        lbb = f(d[4])
        lotteryBlock = TinyBlock.unblob(lbb) if lbb else None

        v = f(d[5])
        vote = ByteArray(v) if v else None

        r = f(d[6])
        revocation = ByteArray(r) if r else None
        return TicketInfo(
            status=d[0].decode("utf-8"),
            purchaseBlock=purchaseBlock,
            maturityHeight=iFunc(d[2]),
            expirationHeight=iFunc(d[3]),
            lotteryBlock=lotteryBlock,
            vote=vote,
            revocation=revocation,
        )

    def serialize(self):
        """
        Serialize the TicketInfo.

        Returns:
            ByteArray: The serialized TicketInfo.
        """
        return ByteArray(TicketInfo.blob(self))


class UTXO(object):
    """
    The UTXO is part of the wallet API. BlockChains create and parse UTXO
    objects and fill fields as required by the Wallet.
    """

    def __init__(
        self,
        address,
        txHash,
        vout,
        ts=None,
        scriptPubKey=None,
        height=-1,
        satoshis=0,
        maturity=0,
        tinfo=None,
    ):
        """
        Contructor for a UTXO.

        Args:
            address (str): The address to which the UTXO pays.
            txHash (ByteArray): The transaction hash of the output's tx.
            vout (int): The output's tx output index.
            ts (int): optional. default None. The Unix timestamp. default None
                for mempool.
            scriptPubKey (ByteArray): optional. default None. The pubkey script.
            height (int): optional. default -1 signifies mempool. The output's
                transaction's block height. default -1 signifies a mempool.
            satoshis (int): optional. default 0. The output value.
            maturity (int): optional. default 0 signifies mature. The height at
                which the output becomes that the output is already mature.
            tinfo (TicketInfo): optional. default None. The ticket info. Tickets
                only.
        """
        self.address = address
        self.txHash = txHash
        self.vout = vout
        self.ts = ts
        self.scriptPubKey = scriptPubKey
        self.height = height
        self.satoshis = satoshis
        self.amount = round(satoshis / 1e8, 8)
        self.maturity = maturity
        self.scriptClass = None
        self.parseScriptClass()
        self.tinfo = tinfo

    @staticmethod
    def blob(utxo):
        """Satisfies the encode.Blobber API"""
        f = encode.filterNone
        return (
            BuildyBytes(0)
            .addData(utxo.address.encode("utf-8"))
            .addData(utxo.txHash)
            .addData(utxo.vout)
            .addData(f(utxo.ts))
            .addData(f(utxo.scriptPubKey))
            .addData(encode.intToBytes(utxo.height, signed=True))
            .addData(utxo.satoshis)
            .addData(utxo.maturity)
            .addData(f(TicketInfo.blob(utxo.tinfo) if utxo.tinfo else None))
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("wrong version for UTXO %d" % ver)
        if len(d) != 9:
            raise AssertionError(
                "wrong number of pushes for UTXO. expected 9 got %d" % len(d)
            )

        iFunc = encode.intFromBytes
        f = encode.extractNone

        tsB = f(d[3])
        ts = iFunc(tsB) if tsB else None

        tinfoB = f(d[8])
        tinfo = TicketInfo.unblob(tinfoB) if tinfoB else None

        utxo = UTXO(
            d[0].decode("utf-8"),
            ByteArray(d[1]),
            encode.intFromBytes(d[2]),
            ts=ts,
            scriptPubKey=f(d[4]),
            height=iFunc(d[5], signed=True),
            satoshis=iFunc(d[6]),
            maturity=iFunc(d[7]),
            tinfo=tinfo,
        )

        utxo.parseScriptClass()
        return utxo

    def serialize(self):
        """
        Serialize the UTXO.

        Returns:
            ByteArray: The serialized UTXO.
        """
        return ByteArray(UTXO.blob(self))

    @staticmethod
    def parse(obj):
        """
        Parse the decoded JSON from dcrdata into a UTXO.

        Args:
            obj (dict): The dcrdata /api/tx response, decoded.
        """
        utxo = UTXO(
            address=obj["address"],
            txHash=reversed(ByteArray(obj["txid"])),
            vout=obj["vout"],
            ts=obj["ts"] if "ts" in obj else None,
            scriptPubKey=ByteArray(obj["scriptPubKey"]),
            height=obj["height"] if "height" in obj else -1,
            satoshis=obj["satoshis"] if "satoshis" in obj else 0,
            maturity=obj["maturity"] if "maturity" in obj else 0,
            tinfo=TicketInfo.parse(obj["tinfo"]) if "tinfo" in obj else None,
        )
        utxo.parseScriptClass()
        return utxo

    @property
    def txid(self):
        """
        The output's transaction ID.

        Returns:
            str: The transaction ID.
        """
        return reversed(self.txHash).hex()

    @txid.setter
    def txid(self, txid):
        """
        Setter for the txid @property.
        """
        self.txHash = reversed(ByteArray(txid))

    def parseScriptClass(self):
        """
        Set the script class.
        """
        if self.scriptPubKey:
            self.scriptClass = txscript.getScriptClass(0, self.scriptPubKey)

    def confirm(self, block, tx, params):
        """
        This output has been mined. Set the block details.

        Args:
            block (msgblock.BlockHeader): The block header.
            tx (dict): The dcrdata transaction.
            params (object): The network parameters.
        """
        self.height = block.height
        self.maturity = (
            block.height + params.CoinbaseMaturity if tx.looksLikeCoinbase() else 0
        )
        self.ts = block.timestamp

    def isSpendable(self, tipHeight):
        """
        isSpendable will be True if the UTXO is considered mature at the
        specified height.

        Args:
            tipHeight (int): The current blockchain tip height.

        Returns:
            bool: True if mature.
        """
        if self.isTicket():
            return False
        if self.maturity:
            return self.maturity <= tipHeight
        return True

    def key(self):
        """
        A unique ID for this UTXO.
        """
        return UTXO.makeKey(self.txid, self.vout)

    @staticmethod
    def makeKey(txid, vout):
        """
        A unique ID for a UTXO.

        Args:
            txid (str): UTXO's transaction ID.
            vout (int): UTXO's transaction output index.
        """
        return txid + "#" + str(vout)

    def setTicketInfo(self, apiTinfo):
        """
        Set the ticket info. Only useful for tickets.

        Args:
            apiTinfo (dict): dcrdata /api/tinfo response.
        """
        self.tinfo = TicketInfo.parse(apiTinfo)
        self.maturity = self.tinfo.maturityHeight

    def isTicket(self):
        """
        isTicket will be True if this is SSTX output.

        Returns:
            bool: True if this is an SSTX output.
        """
        return self.scriptClass == txscript.StakeSubmissionTy

    def isLiveTicket(self):
        """
        isLiveTicket will return True if this is a live ticket.

        Returns:
            bool: True if this is a live ticket.
        """
        return self.tinfo and self.tinfo.status in ("immature", "live")

    def isRevocableTicket(self):
        """
        Returns True if this is an expired or missed ticket.
        Returns:
            bool: True if this is expired or missed ticket.
        """
        return self.tinfo and self.tinfo.status in ("expired", "missed")


class Balance(object):
    """
    Information about an account's balance.
    The `total` attribute will contain the sum of the value of all UTXOs known
    for this wallet. The `available` sum is the same, but without those which
    appear to be from immature coinbase or stakebase transactions.
    """

    def __init__(self, total=0, available=0, staked=0):
        """
        Constructor for a Balance. Units atoms.

        Args:
            total (int): optional. default 0. The total balance.
            available (int): optional. default 0. The available balance.
            staked (int): optional. default 0. The staked balance.
        """
        self.total = total
        self.available = available
        self.staked = staked

    @staticmethod
    def blob(bal):
        """Satisfies the encode.Blobber API"""
        return (
            encode.BuildyBytes(0)
            .addData(bal.total)
            .addData(bal.available)
            .addData(bal.staked)
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, pushes = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("invalid version for Balance %d" % ver)
        if len(pushes) != 3:
            raise AssertionError(
                "wrong number of pushes for Balance. wanted 3, got %d" % len(pushes)
            )
        i = encode.intFromBytes
        return Balance(i(pushes[0]), i(pushes[1]), i(pushes[2]))

    def __repr__(self):
        """
        String representation of the Balance.
        """
        return "Balance(total=%.8f, available=%.8f, staked=%.8f)" % (
            self.total * 1e-8,
            self.available * 1e-8,
            self.staked * 1e-8,
        )


class Account(object):
    """
    Account is a Decred account.
    """

    def __init__(self, pubKeyEncrypted, privKeyEncrypted, name, netID, db=None):
        """
        Args:
            pubKeyEncrypted (ByteArray): The encrypted public key bytes.
            privKeyEncrypted (ByteArray): The encrypted private key bytes.
            name (str): Name for the account.
            netID (str): An identifier that can identify the network for an
                asset. Probably a string such as "testnet".
            db (database.Bucket): A database bucket for the account.
        """
        self.pubKeyEncrypted = pubKeyEncrypted
        self.privKeyEncrypted = privKeyEncrypted
        self.name = name
        self.coinID = BIPID
        self.netID = netID
        self.net = nets.parse(netID)
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
        self.privKey = None  # The private extended key.
        self.extPub = None  # The external branch public extended key.
        self.intPub = None  # The internal branch public extended key.
        self.gapLimit = DefaultGapLimit
        self.tickets = []
        self.stakeStats = TicketStats()
        self.stakePools = []
        self.blockchain = None
        self.signals = None
        self._votingKey = None
        self.utxoDB = None
        self.addressDB = None
        # If a database was provided, load it. This would be the case when
        # the account is first created, as opposed to be unblobbed.
        if db is not None:
            self.load(db)

    @staticmethod
    def blob(acct):
        """Satisfies the encode.Blobber API"""
        return (
            BuildyBytes(0)
            .addData(acct.pubKeyEncrypted)
            .addData(acct.privKeyEncrypted)
            .addData(acct.name.encode("utf-8"))
            .addData(acct.netID.encode("utf-8"))
            .addData(encode.intToBytes(acct.cursorExt, signed=True))
            .addData(acct.cursorInt)
            .addData(acct.gapLimit)
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("invalid Account version %d" % ver)
        if len(d) != 7:
            raise AssertionError(
                "wrong number of pushes for Account. wanted 7, got %d" % len(d)
            )

        iFunc = encode.intFromBytes

        pubEnc = ByteArray(d[0])
        privEnc = ByteArray(d[1])
        name = d[2].decode("utf-8")
        netID = d[3].decode("utf-8")
        acct = Account(pubEnc, privEnc, name, netID)
        acct.cursorExt = iFunc(d[4], signed=True)
        acct.cursorInt = iFunc(d[5])
        acct.gapLimit = iFunc(d[6])
        return acct

    def serialize(self):
        """
        Serialize the Account.

        Returns:
            ByteArray: The serialized Account.
        """
        return ByteArray(Account.blob(self))

    def load(self, db):
        """
        Prep the database and read the account data.

        Args:
            db (database.Bucket): The database.
        """
        self.masterDB = db.child("meta")
        self.utxoDB = db.child("utxos", blobber=UTXO)
        self.utxos = {k: v for k, v in self.utxoDB.items()}
        self.updateStakeStats()
        self.addrIntDB = db.child("internal_addrs", datatypes=("INTEGER", "TEXT"))
        self.internalAddresses = readAddrs(self.addrIntDB)
        self.addrExtDB = db.child("external_addrs", datatypes=("INTEGER", "TEXT"))
        self.externalAddresses = readAddrs(self.addrExtDB)
        self.addrTxDB = db.child(
            "address_txid", datatypes=("TEXT", "BLOB"), unique=False
        )
        txs = self.txs
        for addr, txHash in self.addrTxDB.items():
            if addr not in txs:
                txs[addr] = []
            txs[addr].append(reversed(ByteArray(txHash)).hex())
        self.vspDB = db.child(
            "vsps", datatypes=("TEXT", "BLOB"), blobber=VotingServiceProvider
        )
        # Get the ordered list of stake pools.
        if MetaKeys.vsp in self.masterDB:
            apiKeys = encode.unblobStrList(self.masterDB[MetaKeys.vsp])
            self.stakePools = [self.vspDB[apiKey] for apiKey in apiKeys]

    def open(self, cryptoKey, blockchain, signals):
        """
        Open the Decred account. Runs the parent's method, then performs some
        Decred-specific initialization.
        """
        self.blockchain = blockchain
        self.signals = signals
        self.privKey = self.privateExtendedKey(cryptoKey)
        pubX = self.privKey.neuter()
        self.extPub = pubX.child(EXTERNAL_BRANCH)
        self.intPub = pubX.child(INTERNAL_BRANCH)
        # The voting key is the first non-crazy stake-branch child.
        for i in range(3):
            try:
                self._votingKey = self.privKey.child(STAKE_BRANCH).child(i).privateKey()
                return
            except crypto.CrazyKeyError:
                continue
        # It is realistically impossible to reach here.
        raise Exception("error finding voting key")

    def close(self):
        """
        Close the Decred account. Runs the parent's method, then performs some
        Decred-specific clean up.
        """
        if self.privKey:
            self.privKey.key.zero()
            self.privKey.pubKey.zero()
            self.extPub.key.zero()
            self.extPub.pubKey.zero()
            self.intPub.key.zero()
            self.intPub.pubKey.zero()
            self._votingKey.key.zero()
        self.privKey = None
        self.extPub = None
        self.intPub = None
        self._votingKey = None

    def calcBalance(self, tipHeight=None):
        """
        Calculate the current balance.

        Args:
            tipHeight (int): optional. The current tip height. If not provided,
                the height from the current blockchain.tip will be used.

        Returns:
            Balance: The current balance. The balance is also assigned to the
                Account.balance property.
        """
        tipHeight = (
            tipHeight if tipHeight is not None else self.blockchain.tip["height"]
        )
        tot = 0
        avail = 0
        staked = 0
        for utxo in self.utxoscan():
            tot += utxo.satoshis
            if utxo.isTicket():
                staked += utxo.satoshis
            if utxo.isSpendable(tipHeight):
                avail += utxo.satoshis
        self.balance.total = tot
        self.balance.available = avail
        self.balance.staked = staked
        return self.balance

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
        self.utxos = {u.key(): u for u in blockchainUTXOs}
        self.utxoDB.clear()
        self.utxoDB.batchInsert(self.utxos.items())

    def utxoscan(self):
        """
        A generator for iterating UTXOs. None of the UTXO set modifying
        functions (addUTXO, spendUTXO) should be used during iteration.

        Returns:
            generator(UTXO): A UTXO generator that iterates all known UTXOs.
        """
        for utxo in self.utxos.values():
            yield utxo

    def UTXOsForTxID(self, txid):
        """
        Get any UTXOs with the provided transaction ID.
        Args:
            txid (str): The hex-encoded transaction ID.
        Returns:
            list(UTXO): List of UTXO for the txid.
        """
        return (utxo for utxo in self.utxoscan() if utxo.txid == txid)

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
            tx (MsgTx): A transaction.
        """
        self.mempool[tx.txid()] = tx

    def addTxid(self, addr, txid):
        """
        Add addr and txid to tracked addresses and txids if not already added.

        Args:
            addr (str): Base-58 encoded address.
            txid (str): The hex-encoded transaction ID.
        """
        self.addrTxDB[addr] = reversed(ByteArray(txid)).b
        txs = self.txs
        if addr not in txs:
            txs[addr] = []
        txids = txs[addr]
        if txid not in txids:
            txids.append(txid)
        # Advance the cursors as necessary.
        if addr in self.externalAddresses:
            extIdx = self.externalAddresses.index(addr)
            if extIdx > self.lastSeenExt:
                diff = extIdx - self.lastSeenExt
                self.lastSeenExt = extIdx
                self.cursorExt = max(0, self.cursorExt - diff)
        elif addr in self.internalAddresses:
            intIdx = self.internalAddresses.index(addr)
            if intIdx > self.lastSeenInt:
                diff = intIdx - self.lastSeenInt
                self.lastSeenInt = intIdx
                self.cursorInt = max(0, self.cursorInt - diff)

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
        for utxo in self.UTXOsForTxID(txid):
            utxo.height = blockHeight
            if tx.looksLikeCoinbase():
                # This is a coinbase transaction, set the maturity height.
                utxo.maturity = utxo.height + self.net.CoinbaseMaturity

    def nextBranchAddress(self, branchKey, branchAddrs, branchDB):
        """
        Generate a new address and add it to the list of external addresses.
        Does not move the cursor.

        Args:
            branchKey (ExtendedKey): The branch extended public key.
            branchAddrs (list(string)): The current list of branch addresses.
            branchDB (database.Bucket): The branch address database bucket.

        Returns:
            str: Base-58 encoded address.
        """

        def nextAddr():
            idx = len(branchAddrs)
            try:
                addr = branchKey.deriveChildAddress(idx, self.net)
            except crypto.CrazyKeyError:
                addr = CrazyAddress
            branchAddrs.append(addr)
            branchDB[idx] = addr
            return addr

        for i in range(3):
            addr = nextAddr()
            if addr != CrazyAddress:
                return addr
        raise Exception("failed to generate new address")

    def nextExternalAddress(self):
        """
        Return a new external address. Advances the cursor.

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
                self.nextBranchAddress(self.extPub, extAddrs, self.addrExtDB)
            addr = extAddrs[idx]
        if self.blockchain:
            self.blockchain.subscribeAddresses(addr)
        return addr

    def nextInternalAddress(self):
        """
        Return a new internal address. Advances the cursor.

        Returns:
            str: Base-58 encoded address.
        """
        intAddrs = self.internalAddresses
        addr = CrazyAddress
        # Though unlikely, if an out or range key is generated, the account will
        # generate an additional address
        while addr == CrazyAddress:
            # gap policy is to wrap. Wrapping brings the cursor back to index 1,
            # since index zero is the last seen address.
            self.cursorInt += 1
            if self.cursorInt > self.gapLimit:
                self.cursorInt = 1
            idx = self.lastSeenInt + self.cursorInt
            while len(intAddrs) < idx + 1:
                self.nextBranchAddress(self.intPub, intAddrs, self.addrIntDB)
            addr = intAddrs[idx]
        return addr

    def lastSeen(self, addrs, default=0):
        """
        Find the index of the last seen address in the list of addresses.
        The last seen address is taken as the last address for which there is an
        entry in the self.txs dict.

        Args:
            addrs (list(string)): The list of addresses.

        Returns:
            int: The highest index of all seen addresses in the list.
        """
        lastSeen = default
        for i, addr in enumerate(addrs):
            if addr in self.txs:
                lastSeen = i
        return lastSeen

    def generateGapAddresses(self):
        """
        Generate addresses up to gap addresses after the cursor. Do not move the
        cursor.

        Returns:
            list(str): Newly generated addresses.
        """
        if self.extPub is None:
            log.warning("attempting to generate gap addresses on a closed account")
        minExtLen = self.lastSeenExt + self.gapLimit + 1
        newAddrs = self.generateBranchGaps(
            self.extPub, self.externalAddresses, self.addrExtDB, minExtLen
        )
        minIntLen = self.lastSeenInt + self.gapLimit + 1
        newAddrs.extend(
            self.generateBranchGaps(
                self.intPub, self.internalAddresses, self.addrIntDB, minIntLen
            )
        )
        return newAddrs

    def generateBranchGaps(self, key, addrs, db, reqLen):
        """
        Generate gap addresses the specified branch.

        Args:
            key (crypto.ExtendedKey): The branch extended key.
            addrs list(str): The current branch addresses.
            db (database.Bucket): The branch address database.
            reqLen (int): The minimum length of the resulting address list,
                formed by appending to the addrs list.
        """
        newAddrs = []
        while len(addrs) < reqLen:
            self.nextBranchAddress(key, addrs, db)
            newAddrs.append(addrs[-1])
        return newAddrs

    def gapAddrs(self):
        """
        A list of addresses which have been generated but have not yet been
        seen. Any addresses before the last seen address will be excluded.
        Addresses come from both the external and internal branch.

        Returns:
            list(str): Gap addresses.
        """
        return filterCrazyAddress(
            self.internalAddresses[self.lastSeenInt :]
            + self.externalAddresses[self.lastSeenExt :]
        )

    def currentAddress(self):
        """
        Get the external address at the cursor. The cursor is not moved.

        Returns:
            str: Base-58 encoded address.
        """
        return self.externalAddresses[self.lastSeenExt + self.cursorExt]

    def privateExtendedKey(self, cryptoKey):
        """
        Decode the private extended key for the account using the provided
        SecretKey.

        Args:
            pw (SecretKey): The secret key.

        Returns:
            crypto.ExtendedKey: The current account's decoded private key.
        """
        return crypto.decodeExtendedKey(self.net, cryptoKey, self.privKeyEncrypted)

    def publicExtendedKey(self, cryptoKey):
        """
        Decode the public extended key for the account using the provided
        SecretKey.

        Args:
            pw (SecretKey): The secret key.

        Returns:
            crypto.ExtendedKey: The current account's decoded public key.
        """
        return crypto.decodeExtendedKey(self.net, cryptoKey, self.pubKeyEncrypted)

    def branchAndIndex(self, addr):
        """
        Find the branch and index of the address.

        Args:
            addr (str): Base-58 encoded address.

        Returns:
            int: Internal (1) or external (0) branch, or None if not found.
            int: Address index, or None if not found.
        """
        branch, idx = None, None
        if addr in self.externalAddresses:
            branch = EXTERNAL_BRANCH
            idx = self.externalAddresses.index(addr)
        elif addr in self.internalAddresses:
            branch = INTERNAL_BRANCH
            idx = self.internalAddresses.index(addr)
        return branch, idx

    def privKeyForAddress(self, addr):
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

    def addUTXO(self, utxo):
        """
        Add the UTXO. Update the stake stats if this is a ticket.
        """
        self.utxos[utxo.key()] = utxo
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

    def caresAboutTxid(self, txid):
        """
        Indicates whether the account has any UTXOs with this transaction ID, or
        has this transaction in mempool.

        Args:
            txid (str): The hex-encoded transaction ID.

        Returns:
            bool: `True` if we are watching the txid.
        """
        return txid in self.mempool or self.hasUTXOwithTxID(txid)

    def hasUTXOwithTxID(self, txid):
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

    def allAddresses(self):
        """
        Return a list of all addresses, internal and external, that have been
        created for this account. Also includes the VSP ticket addresses.

        Returns:
            list(str): List of base-58 encoded addresses.
        """
        return self.addTicketAddresses(
            filterCrazyAddress(self.internalAddresses + self.externalAddresses)
        )

    def watchAddrs(self):
        """
        A list of addresses to monitor. These addresses will be submitted to
        the BlockChain to receive a feed of updates. This function does not
        return internal addresses that have already been seen.

        Returns:
            list(str): List of base-58 encoded addresses.
        """
        a = set()
        a = a.union((utxo.address for utxo in self.utxoscan()))
        a = a.union(self.externalAddresses)
        a = a.union((a for a in self.internalAddresses if a not in self.txs))
        return self.addTicketAddresses(filterCrazyAddress(a))

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
        return crypto.AddressSecpPubKey(
            self.votingKey().pub.serializeCompressed(), self.net
        ).string()

    def setPool(self, pool):
        """
        Set the specified pool as the default.

        Args:
            pool (vsp.VotingServiceProvider): The stake pool object.
        """
        if not isinstance(pool, VotingServiceProvider):
            raise AssertionError("setPool given wrong type %s" % type(pool))
        self.stakePools = [pool] + [
            p for p in self.stakePools if p.apiKey != pool.apiKey
        ]
        self.vspDB[pool.apiKey] = pool
        self.masterDB[MetaKeys.vsp] = encode.blobStrList(
            [p.apiKey for p in self.stakePools]
        )
        bc = self.blockchain
        addr = pool.purchaseInfo.ticketAddress
        for txid in bc.txsForAddr(addr):
            self.addTxid(addr, txid)
        for utxo in bc.UTXOs([addr]):
            self.addUTXO(utxo)
        self.updateStakeStats()
        self.signals.balance(self.calcBalance())

    def hasPool(self):
        """
        hasPool will return True if the wallet has at least one pool set.
        """
        return self.stakePool() is not None

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
        self.signals.balance(self.calcBalance())

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
                _, addresses, _ = txscript.extractPkScriptAddrs(
                    0, txout.pkScript, self.net
                )
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
            self.signals.balance(self.calcBalance())

    def sendToAddress(self, value, address, feeRate=None):
        """
        Send the value to the address.

        Args:
            value int: The amount to send, in atoms.
            address str: The base-58 encoded pubkey hash.

        Returns:
            MsgTx: The newly created transaction on success, `False` on failure.
        """
        keysource = KeySource(
            priv=self.privKeyForAddress, internal=self.nextInternalAddress,
        )
        tx, spentUTXOs, newUTXOs = self.blockchain.sendToAddress(
            value, address, keysource, self.getUTXOs, feeRate
        )
        self.addMempoolTx(tx)
        self.spendUTXOs(spentUTXOs)
        for utxo in newUTXOs:
            self.addUTXO(utxo)
        self.signals.balance(self.calcBalance())
        return tx

    def purchaseTickets(self, qty, price):
        """
        purchaseTickets completes the purchase of the specified tickets. The
        Account uses the blockchain to do the heavy lifting, but must prepare
        the TicketRequest and KeySource and gather some other account- related
        information.
        """
        keysource = KeySource(
            priv=self.privKeyForAddress, internal=self.nextInternalAddress,
        )
        pool = self.stakePool()
        pi = pool.purchaseInfo
        req = TicketRequest(
            minConf=0,
            expiry=0,
            spendLimit=int(round(price * qty * 1.1 * 1e8)),  # convert to atoms here
            poolAddress=pi.poolAddress,
            votingAddress=pi.ticketAddress,
            ticketFee=0,  # use network default
            poolFees=pi.poolFees,
            count=qty,
            txFee=0,  # use network default
        )
        txs, spentUTXOs, newUTXOs = self.blockchain.purchaseTickets(
            keysource, self.getUTXOs, req
        )
        # Add the split transactions
        self.addMempoolTx(txs[0])
        # Add all tickets
        for tx in txs[1]:
            self.addMempoolTx(tx)
        # Store the txids.
        self.tickets.extend([tx.txid() for tx in txs[1]])
        self.spendUTXOs(spentUTXOs)
        for utxo in newUTXOs:
            self.addUTXO(utxo)
        self.signals.balance(self.calcBalance())
        return txs[1]

    def revokeTickets(self):
        """
        Iterate through missed and expired tickets and revoke them.

        Returns:
            bool: whether or not an error occured.
        """
        revocableTickets = (
            utxo.txid for utxo in self.utxos.values() if utxo.isRevocableTicket()
        )
        txs = [self.blockchain.tx(txid) for txid in revocableTickets]
        for tx in txs:
            redeemHash = crypto.AddressScriptHash(
                self.net.ScriptHashAddrID,
                txscript.extractStakeScriptHash(tx.txOut[0].pkScript, opcode.OP_SSTX),
            )
            redeemScript = next(
                (
                    encode.decodeBA(p.purchaseInfo.script)
                    for p in self.stakePools
                    if p.purchaseInfo.ticketAddress == redeemHash.string()
                ),
                None,
            )
            if not redeemScript:
                raise Exception("did not find redeem script for hash %s" % redeemHash)

            keysource = KeySource(
                # This will need to change when we start using different
                # addresses for voting.
                priv=lambda _: self._votingKey,
                internal=lambda: "",
            )
            self.blockchain.revokeTicket(tx, keysource, redeemScript)

    def sync(self):
        """
        Synchronize the UTXO set with the server. This should be the first
        action after the account is opened or changed.
        """
        blockchain, signals = self.blockchain, self.signals
        signals.balance(self.calcBalance())
        self.generateGapAddresses()

        # If there is a chosen stake pool, sync the purchaseInfo.
        # TODO: Save purchase info
        stakePool = self.stakePool()
        if stakePool:
            try:
                stakePool.getPurchaseInfo()
            except Exception as e:
                log.error("error getting VSP purchase info: %s" % e)

        # First, look at addresses that have been generated but not seen. Run in
        # loop until the gap limit is reached.
        requestedTxs = 0
        addrs = self.gapAddrs()
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

        self.updateStakeStats()
        pool = self.stakePool()
        if pool:
            pool.authorize(self.votingAddress())

        # Subscribe to block and address updates.
        blockchain.addressReceiver = self.addressSignal
        blockchain.subscribeBlocks(self.blockSignal)
        watchAddresses = self.watchAddrs()
        if watchAddresses:
            blockchain.subscribeAddresses(watchAddresses)
        # Signal the new balance.
        signals.balance(self.calcBalance())

        return True


def readAddrs(db):
    """
    Read and verify the address index database. Create a list of addresses.

    Args:
        db (database.Bucket): The address table that maps address to child
            index.

    Returns:
        list(string): The list of addresses.
    """
    pairs = sorted(db.items(), key=lambda pair: pair[0])
    if pairs and len(pairs) != pairs[-1][0] + 1:
        raise AssertionError("address index mismatch")
    return [pair[1] for pair in pairs]
