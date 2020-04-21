"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details

DcrdataClient.endpointList() for available enpoints.
"""

import atexit
import calendar
import json
import time
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from decred import DecredError
from decred.crypto import crypto
from decred.dcr import addrlib
from decred.util import database, tinyhttp, ws
from decred.util.encode import ByteArray
from decred.util.helpers import formatTraceback, getLogger, makeWebsocketURL

from . import account, agenda, txscript
from .wire import msgblock, msgtx, wire


log = getLogger("DCRDATA")

VERSION = "0.0.1"
GET_HEADERS = {"User-Agent": "PyDcrData/%s" % VERSION}
POST_HEADERS = {
    "User-Agent": "tinydecred/%s" % VERSION,
    "Content-Type": "application/json; charset=utf-8",
}
WS_DONE = object()

# These two come from dcrdata, and are potentially subject to change, though
# unlikely.
MaxInsightAddrsTxns = 250
AddrsPerRequest = 25


class DcrdataError(DecredError):
    pass


class InsufficientFundsError(DecredError):
    """
    Available account balance too low for requested funds.
    """

    pass


class DcrdataPath:
    """
    DcrdataPath represents some point along a URL. It may just be a node that
    is not an endpoint, or it may be an endpoint, in which case its `get`
    method will be a valid API call. If it is a node of a longer URL,
    the following nodes are available as attributes. e.g. if this is node A
    along the URL base/A/B, then node B is available as client.A.B.
    """

    def __init__(self):
        self.subpaths = {}
        self.callSigns = []

    def getSubpath(self, subpathPart):
        if subpathPart in self.subpaths:
            return self.subpaths[subpathPart]
        p = self.subpaths[subpathPart] = DcrdataPath()
        return p

    def addCallsign(self, argList, template):
        """
        Some paths have multiple call signatures or optional parameters.
        Keeps a list of arguments associated with path templates to differentiate.
        """
        self.callSigns.append((argList, template))

    def getCallsignPath(self, *args, **kwargs):
        """
        Find the path template that matches the passed arguments.
        """
        argLen = len(args) if args else len(kwargs)
        for argList, template in self.callSigns:
            if len(argList) != argLen:
                continue
            if args:
                url = template % args
                if len(kwargs):
                    url += "?" + urlencode(kwargs)
                return url
            if all([x in kwargs for x in argList]):
                return template % tuple(kwargs[x] for x in argList)
        raise DcrdataError(
            "Supplied arguments, %r, do not match any of the know call signatures, %r."
            % (args if args else kwargs, [argList for argList, _ in self.callSigns]),
        )

    def __getattr__(self, key):
        if key in self.subpaths:
            return self.subpaths[key]
        raise DcrdataError("No subpath %s found in datapath" % (key,))

    def __call__(self, *args, **kwargs):
        return tinyhttp.get(self.getCallsignPath(*args, **kwargs), headers=GET_HEADERS)

    def post(self, data):
        return tinyhttp.post(self.getCallsignPath(), data, headers=POST_HEADERS)


# TODO: get the full list here.
InsightPaths = [
    "/tx/send",
    "/insight/api/addr/{address}/utxo",
    "/insight/api/addr/{address}",
    "/insight/api/tx/send",
    "/insight/api/addrs/{addresses}/txs",
]


class DcrdataClient:
    """
    DcrdataClient represents the base node.
    """

    timeFmt = "%Y-%m-%d %H:%M:%S"
    rfc3339Z = "%Y-%m-%dT%H:%M:%SZ"

    def __init__(self, url, emitter=None):
        """
        Build the DcrdataPath tree.

        Args:
            url (string): the URL to a DCRData server, e.g.
                http://explorer.dcrdata.org/.
            emitter (function): a function that accepts incoming subscription
                messages as JSON-decoded dicts as the only parameter.
        """
        url = urlsplit(url)
        # Remove any path.
        self.baseURL = urlunsplit((url.scheme, url.netloc, "/", "", ""))
        # Add the "/api" path.
        self.baseApi = urlunsplit((url.scheme, url.netloc, "/api/", "", ""))
        self.psURL = makeWebsocketURL(self.baseURL, "ps")
        self.ps = None
        self.subscribedAddresses = []
        self.emitter = emitter if emitter else lambda msg: None
        atexit.register(self.close)
        root = self.root = DcrdataPath()
        self.listEntries = []
        # /list returns a json list of enpoints with parameters in template format,
        # base/A/{param}/B
        listURL = urljoin(self.baseApi, "list")
        endpoints = tinyhttp.get(listURL, headers=GET_HEADERS)
        endpoints += InsightPaths

        def getParam(part):
            if part.startswith("{") and part.endswith("}"):
                return part[1:-1]
            return None

        pathlog = []
        for path in endpoints:
            path = path.rstrip("/")
            if path in pathlog or path == "":
                continue
            pathlog.append(path)
            baseURL = self.baseURL if "insight" in path else self.baseApi
            params = []
            pathSequence = []
            templateParts = []
            # split the path into an array for nodes and an array for parameters
            for i, part in enumerate(path.strip("/").split("/")):
                param = getParam(part)
                if param:
                    params.append(param)
                    templateParts.append("%s")
                else:
                    pathSequence.append(part)
                    templateParts.append(part)
            pathPointer = root
            for pathPart in pathSequence:
                pathPointer = pathPointer.getSubpath(pathPart)
            pathPointer.addCallsign(params, baseURL + "/".join(templateParts))
            if len(pathSequence) == 1:
                continue
            self.listEntries.append(
                ("%s(%s)" % (".".join(pathSequence), ", ".join(params)), path)
            )

    def __getattr__(self, key):
        return getattr(self.root, key)

    def close(self):
        if self.ps:
            self.ps.close()
            self.ps = None

    def endpointList(self):
        return [entry[1] for entry in self.listEntries]

    def endpointGuide(self):
        """
        Print one endpoint per line.
        Each line shows a translation from Python notation to a URL.
        """
        print("\n".join(["%s  ->  %s" % entry for entry in self.listEntries]))

    def psClient(self):
        if self.ps is None:

            def on_message(ws, msg):
                try:
                    msg = json.loads(msg)
                    # Ignore pings. They are used as a connection probe and do
                    # not require a response.
                    if msg.get("event") == "ping":
                        return
                except json.JSONDecodeError:
                    # If it's not JSON, let the caller handle the string.
                    pass
                self.emitter(msg)

            def on_close(ws):
                self.emitter(WS_DONE)

            def on_error(ws, error):
                log.error(f"pubsub error: {error}")

            self.ps = ws.Client(
                url=self.psURL,
                on_message=on_message,
                on_close=on_close,
                on_error=on_error,
            )

        return self.ps

    def subscribeAddresses(self, addrs):
        """
        addrs: list(str) or str
            A base58 encoded address or list of addresses to subscribe to
        """
        if isinstance(addrs, str):
            addrs = [addrs]
        ps = self.psClient()
        subscribed = self.subscribedAddresses
        for a in addrs:
            if a in subscribed:
                continue
            subscribed.append(a)
            ps.send(Sub.address(a))

    def subscribeBlocks(self):
        ps = self.psClient()
        ps.send(Sub.newblock)

    @staticmethod
    def timeStringToUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, DcrdataClient.timeFmt))

    @staticmethod
    def RFC3339toUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, DcrdataClient.rfc3339Z))


_subcounter = 0


def makeSubscription(eventID):
    global _subcounter
    _subcounter += 1
    return json.dumps(
        {
            "event": "subscribe",
            "message": {"request_id": _subcounter, "message": eventID},
        }
    )


class Sub:
    newblock = makeSubscription("newblock")
    mempool = makeSubscription("mempool")
    newtxs = makeSubscription("newtxs")
    blockchainSync = makeSubscription("blockchainSync")

    def address(addr):
        global _subcounter
        _subcounter += 1
        return json.dumps(
            {
                "event": "subscribe",
                "message": {"request_id": _subcounter, "message": "address:%s" % addr},
            }
        )


class TicketPoolInfo:
    """
    Ticket pool statistics.
    """

    def __init__(
        self, height, size, value, valAvg, winners,
    ):
        """
        height (int): Height this data was taken.
        size (int): Number of live tickets.
        value (float): Total value of live tickets.
        valAvg (float): Average value of one ticket.
        winners (list(str)): Winners of this block.
        """
        self.height = height
        self.size = size
        self.value = value
        self.valAvg = valAvg
        self.winners = winners

    @staticmethod
    def parse(obj):
        return TicketPoolInfo(
            height=obj["height"],
            size=obj["size"],
            value=obj["value"],
            valAvg=obj["valavg"],
            winners=[winner for winner in obj["winners"]],
        )


def makeOutputs(pairs, netParams):
    """
    makeOutputs creates a slice of transaction outputs from a pair of address
    strings to amounts.  This is used to create the outputs to include in newly
    created transactions from a JSON-derived dict describing the output
    destinations and amounts.

    Args:
        pairs (tuple(str, int)): Base58-encoded address strings and atoms to
            send to the address.
        netParams (module): Network parameters.

    Returns:
        list(msgtx.TxOut): Transaction outputs.
    """
    outputs = []
    for idx, (addrStr, amt) in enumerate(pairs):
        # Make sure amt is atoms.
        if not isinstance(amt, int):
            raise DecredError(f"Decred amount #{idx} is not an integer")
        if amt < 0:
            raise DecredError(f"Decred amount #{idx} is negative")
        pkScript = txscript.makePayToAddrScript(addrStr, netParams)
        outputs.append(msgtx.TxOut(value=amt, pkScript=pkScript))
    return outputs


def checkOutput(output, fee):
    """
    checkOutput performs simple consensus and policy tests on a transaction
    output.

    Args:
        output (TxOut): The output to check
        fee (float): The transaction fee rate (/kB).

    Raises:
        DecredError if an output is deemed invalid.
    """
    if output.value < 0:
        raise DecredError("transaction output amount is negative")
    if output.value > txscript.MaxAmount:
        raise DecredError("transaction output amount exceeds maximum value")
    if output.value == 0:
        raise DecredError("zero-value output")
    # need to implement these
    if txscript.isDustOutput(output, fee):
        raise DecredError("policy violation: transaction output is dust")


def hashFromHex(s):
    """
    Parse a transaction hash or block hash from a hexadecimal string.

    Args:
        s (str): A byte-reversed, hexadecimal string encoded hash.

    Returns:
        ByteArray: Decoded hash
    """
    return reversed(ByteArray(s))


def hexFromHash(h):
    """
    Parse a tx or block hash from a ByteArray.

    Args:
        h (str): A hash of the block or transaction.
    """
    return reversed(ByteArray(h)).hex()


class DcrdataBlockchain:
    """
    DcrdataBlockchain implements the Blockchain API from tinydecred.api.
    """

    def __init__(self, db, netParams, datapath, skipConnect=False):
        """
        Args:
            db (database.Bucket | database.KeyValueDatabase | filepath):
                the database or a filepath. If a filepath, a new database
                will be created.
            netParams module: the network parameters.
            datapath str: a URL for a dcrdata server.
            skipConnect bool: skip initial connection to dcrdata.
        """
        # Allow string arguments for database.
        self.ownsDB = False
        if not isinstance(db, (database.Bucket, database.KeyValueDatabase)):
            self.ownsDB = True
            db = database.KeyValueDatabase(db)
        self.db = db
        self.netParams = netParams
        self.datapath = datapath
        self.dcrdata = None
        self.txDB = db.child("tx", blobber=msgtx.MsgTx)
        self.heightMap = db.child("height", datatypes=("INTEGER", "BLOB"))
        self.headerDB = db.child("header", blobber=msgblock.BlockHeader)
        self.txBlockMap = db.child("blocklink")
        self.tipHeight = -1
        self.subsidyCache = txscript.SubsidyCache(netParams)
        self.addrSubscribers = {}
        self.blockSubscribers = []
        if not skipConnect:
            self.connect()

    def connect(self):
        """
        Connect to dcrdata.
        """
        self.dcrdata = DcrdataClient(self.datapath, emitter=self.pubsubSignal)
        self.updateTip()

    def changeServer(self, url):
        """
        Attempt to change the current DcrdataClient to the provided URL. The
        client is only changed when all of the following are true.

            1. The connection is successfully created.
            2. Block and address subscribers are resubscribed.
            3. The tip is successfully updated.

        If a failure is encountered at any step, the old client is kept.

        Args:
            url (str): The new dcrdata URL.
        """
        oldClient = self.dcrdata
        self.dcrdata = DcrdataClient(url, emitter=self.pubsubSignal)
        try:
            if self.blockSubscribers:
                self.dcrdata.subscribeBlocks()
            if self.addrSubscribers:
                addrGroups = {}
                for addr, receiver in self.addrSubscribers.items():
                    rid = id(receiver)
                    if rid not in addrGroups:
                        addrGroups[rid] = dict(receiver=receiver, addrs=[])
                    addrGroups[rid]["addrs"].append(addr)
                for group in addrGroups.values():
                    self.subscribeAddresses(group["addrs"], group["receiver"])
                self.updateTip()
            self.datapath = url
            oldClient.close()

        except Exception as e:
            self.dcrdata = oldClient
            raise e

    def close(self):
        """
        close any underlying connections.
        """
        if self.dcrdata:
            self.dcrdata.close()
        if self.ownsDB:
            self.db.close()

    def subscribeBlocks(self, receiver):
        """
        Subscribe to new block notifications.

        Args:
            receiver (func(object)): A function or method that accepts the block
                notifications.
        """
        self.blockSubscribers.append(receiver)
        if len(self.blockSubscribers) == 1:
            self.dcrdata.subscribeBlocks()

    def getAgendasInfo(self):
        """
        The agendas info that is used for voting.

        Returns:
            AgendasInfo: the current agendas.
        """
        return agenda.AgendasInfo.parse(self.dcrdata.stake.vote.info())

    def subscribeAddresses(self, addrs, receiver):
        """
        Subscribe to notifications for the provided addresses.

        Args:
            addrs (list(str)): List of base-58 encoded addresses.
            receiver (func(object)): A function or method that accepts the address
                notifications.
        """
        log.debug("subscribing to addresses %s" % repr(addrs))
        for addr in addrs:
            self.addrSubscribers[addr] = receiver
        self.dcrdata.subscribeAddresses(addrs)

    def processNewUTXO(self, utxo):
        """
        Processes an as-received blockchain utxo.
        Check for coinbase or stakebase, and assign a maturity as necessary.

        Args:
            utxo account.UTXO: A new unspent transaction output from blockchain.

        Returns:
            bool: True if no errors are encountered.
        """
        utxo = account.UTXO.parse(utxo)
        tx = self.tx(utxo.txid)
        if tx.looksLikeCoinbase():
            # This is a coinbase or stakebase transaction. Set the maturity.
            utxo.maturity = utxo.height + self.netParams.CoinbaseMaturity
        if utxo.isTicket():
            # Mempool tickets will be returned from the utxo endpoint, but
            # the tinfo endpoint is an error until mined.
            utxo.tinfo = self.ticketInfo(utxo.txid)
        return utxo

    def UTXOs(self, addrs):
        """
        UTXOs will produce any known UTXOs for the list of addresses.

        Args:
            addrs (list(str)): List of base-58 encoded addresses.
        """
        utxos = []
        addrCount = len(addrs)
        get = lambda addrs: self.dcrdata.insight.api.addr.utxo(",".join(addrs))
        for i in range(addrCount // AddrsPerRequest + 1):
            start = i * AddrsPerRequest
            end = start + AddrsPerRequest
            if start < addrCount:
                ads = addrs[start:end]
                utxos += [self.processNewUTXO(u) for u in get(ads)]
        return utxos

    def txidsForAddr(self, addr):
        """
        Get the transaction IDs for the provided address.

        Args:
            addrs (string): Base-58 encoded address
        """
        addrInfo = self.dcrdata.insight.api.addr(addr)
        if "transactions" not in addrInfo:
            return []
        return addrInfo["transactions"]

    def addrsHaveTxs(self, addrs):
        """
        Return True if there are any transactions for the list of addresses.
        Used as part of the account discovery process.

        Args:
            addrs list(string): The list of addresses to check.
        """

        def gettxs(addrs):
            # 'from' is reserved, so I'll pass it like this.
            return self.dcrdata.insight.api.addrs.txs(
                ",".join(addrs), **{"from": 0, "to": 1}
            ).get("items")

        addrCount = len(addrs)
        for i in range(addrCount // AddrsPerRequest + 1):
            start = i * AddrsPerRequest
            end = start + AddrsPerRequest
            if start < addrCount:
                ads = addrs[start:end]
                if gettxs(ads):
                    return True
        return False

    def txVout(self, txid, vout):
        """
        Get a UTXO from the outpoint. The UTXO will not have the address set.

        Args:
            txid str: hex-encoded txid.
            vout int: the chosen tx output index.
        """
        tx = self.tx(txid)
        txout = tx.txOut[vout]
        utxo = account.UTXO(
            address=None,
            txHash=reversed(ByteArray(txid)),
            vout=vout,
            scriptPubKey=txout.pkScript,
            satoshis=txout.value,
        )
        self.confirmUTXO(utxo, None, tx)
        return utxo

    def ticketInfo(self, txid):
        """
        Get the Ticket Info for txid.

        Args:
            txid (str): The tickets txid.

        Returns:
            TicketInfo: The txid's ticket info.
        """
        # Mempool tickets will be returned from the utxo endpoint, but the
        # tinfo endpoint is an error until mined.
        try:
            tinfo = account.TicketInfo.parse(self.dcrdata.tx.tinfo(txid))
        except Exception:
            tinfo = account.TicketInfo("mempool", None, 0, 0)

        return tinfo

    def tx(self, txid):
        """
        Get the MsgTx. Retreive it from the blockchain if necessary.

        Args:
            txid (str): A hex encoded transaction ID to fetch.

        Returns:
            MsgTx: The transaction.
        """
        hashKey = hashFromHex(txid).bytes()
        try:
            return self.txDB[hashKey]
        except database.NoValueError:
            try:
                # Grab the hex encoded transaction
                txHex = self.dcrdata.tx.hex(txid)
                msgTx = msgtx.MsgTx.deserialize(ByteArray(txHex))
                self.txDB[hashKey] = msgTx
                return msgTx
            except Exception as e:
                log.warning(
                    "unable to retrieve tx data from dcrdata at %s: %s"
                    % (self.dcrdata.baseURL, e)
                )
        raise DecredError("failed to retrieve transaction")

    def tinyBlockForTx(self, txid):
        """
        Get the TinyBlock for txid.

        Args:
            txid(str): The transaction ID for the block.

        Returns:
            account.TinyBlock: The block hash and height.
        """
        block = self.blockForTx(txid)
        if not block:
            return None
        return account.TinyBlock(block.cachedHash(), block.height)

    def blockForTx(self, txid):
        """
        Get the BlockHeader for the transaction.

        Args:
            txid (str): The transaction ID.

        Returns:
            msgblock.BlockHeader: The block header or None.
        """
        txHash = hashFromHex(txid).bytes()
        try:
            # Try to get the blockhash from the database.
            bHash = self.txBlockMap[txHash]
            return self.blockHeader(hexFromHash(ByteArray(bHash)))
        except database.NoValueError:
            # If the blockhash is not in the database, get it from dcrdata
            decodedTx = self.dcrdata.tx(txid)
            # Make sure the block hash is there and is not empty.
            try:
                hexHash = decodedTx["block"]["blockhash"]
                hexHash[0]
            except (KeyError, IndexError):
                return None
            header = self.blockHeader(hexHash)
            self.txBlockMap[txHash] = header.cachedHash().bytes()
            return header

    def ticketForTx(self, txid, netParams):
        """
        Retrieve the ticket with txid on netParams. If tinfo data is not found
        the ticket will be given "mempool" status.

        Args:
            txid (str): The ticket's transaction ID.
            netparams (module): The network parameters.

        Returns:
            UTXO: The ticket.
        """
        tx = self.tx(txid)
        if not tx.isTicket():
            raise DecredError(f"Not a ticket: {txid}")
        block = self.blockForTx(txid)
        tinfo = self.ticketInfo(txid)
        return account.UTXO.ticketFromTx(tx, netParams, block=block, tinfo=tinfo)

    def ticketInfoForSpendingTx(self, txid, netParams):
        """
        Get ticket info for the ticket that txid votes or revokes.

        Args:
            txid (str): The txid of the spending tx.
            netParams (module): Network parameters.

        Returns:
            TicketInfo: The ticket info for the ticket spent by txid.
        """
        tx = self.tx(txid)
        isVote = txscript.isSSGen(tx)
        idx = 1 if isVote else 0
        ticketTxid = tx.txIn[idx].previousOutPoint.txid()
        ticket = self.tx(ticketTxid)
        purchaseBlock = self.tinyBlockForTx(ticketTxid)
        lotteryBlock = self.tinyBlockForTx(tx.txid())

        return account.TicketInfo.fromSpendingTx(
            ticket, tx, purchaseBlock, lotteryBlock, netParams
        )

    def blockHeader(self, hexHash):
        """
        blockHeader will produce a blockHeader implements the BlockHeader API.

        Args:
            bHash (str): The block hash of the block header.

        Returns:
            BlockHeader: An object which implements the BlockHeader API.
        """
        try:
            return self.headerDB[hashFromHex(hexHash).bytes()]
        except database.NoValueError:
            try:
                block = self.dcrdata.block.hash.header.raw(hexHash)
                blockHeader = msgblock.BlockHeader.deserialize(block["hex"])
                self.saveBlockHeader(blockHeader)
                return blockHeader
            except Exception as e:
                log.warning("unable to retrieve block header: %s" % formatTraceback(e))
        raise DecredError("failed to get block header for block %s" % hexHash)

    def blockHeaderByHeight(self, height):
        """
        Get the block header by height. The block header is retrieved from the
        blockchain if necessary, in which case it is stored.

        Args:
            height int: The block height

        Returns:
            BlockHeader: The block header.
        """
        try:
            hashKey = self.heightMap[height]
            return self.headerDB[hashKey]
        except database.NoValueError:
            try:
                hexBlock = self.dcrdata.block.header.raw(idx=height)
                blockHeader = msgblock.BlockHeader.deserialize(hexBlock["hex"])
                self.saveBlockHeader(blockHeader)
                return blockHeader
            except Exception as e:
                log.warning(f"unable to retrieve block header: {formatTraceback(e)}")
        raise DecredError("failed to get block header at height %i" % height)

    def bestBlock(self):
        """
        bestBlock will produce a decoded block as a Python dict.
        """
        return self.dcrdata.block.best()

    def ticketPoolInfo(self):
        """
        The current ticket pool info.

        Returns:
            TicketPoolInfo: the ticket pool info.
        """
        return TicketPoolInfo.parse(self.dcrdata.stake.pool())

    def nextStakeDiff(self):
        """
        Get the estimated next stake difficulty a.k.a. ticket price.

        Returns:
            int: The ticket price.
        """
        return int(round(self.dcrdata.stake.diff()["estimates"]["expected"] * 1e8))

    def stakeDiff(self):
        """
        Get the current stake difficulty a.k.a. ticket price.

        Returns:
            int: The ticket price.
        """
        return int(round(self.dcrdata.stake.diff()["next"] * 1e8))

    def updateTip(self):
        """
        Update the tip block. If the wallet is subscribed to block updates,
        this can be used sparingly.
        """
        try:
            self.tipHeight = self.bestBlock()["height"]
        except Exception as e:
            log.error("failed to retrieve tip from blockchain: %s" % formatTraceback(e))
            raise DecredError("no tip data retrieved")

    def relayFee(self):
        """
        Return the current transaction fee.

        Returns:
            int: Atoms per kB of encoded transaction.
        """
        return txscript.DefaultRelayFeePerKb

    def saveBlockHeader(self, header):
        """
        Save the block header to the database.

        Args:
            header (BlockHeader): The block header to save.
        """
        bHash = header.cachedHash().bytes()
        self.heightMap[header.height] = bHash
        self.headerDB[bHash] = header

    def sendToAddress(self, value, address, keysource, utxosource, feeRate=None):
        """
        Send the amount in atoms to the specified address.

        Args:
            value int: The amount to send, in atoms.
            address str: The base-58 encoded address.
            keysource func(str) -> PrivateKey: A function that returns the
                private key for an address.
            utxosource func(int, func(UTXO) -> bool) -> list(UTXO): A function
                that takes an amount in atoms, and an optional filtering
                function. utxosource returns a list of UTXOs that sum to >= the
                amount. If the filtering function is provided, UTXOs for which
                the  function return a falsey value will not be included in the
                returned UTXO list.
            MsgTx: The newly created transaction on success, `False` on failure.
        """
        self.updateTip()
        outputs = makeOutputs([(address, value)], self.netParams)
        return self.sendOutputs(outputs, keysource, utxosource, feeRate)

    def broadcast(self, txHex):
        """
        Broadcast the hex encoded transaction to dcrdata.

        Args:
            txHex (str): Hex-encoded serialized transaction.
        """
        try:
            log.debug("sending %r to dcrdata" % txHex)
            self.dcrdata.insight.api.tx.send.post({"rawtx": txHex})
            return True
        except Exception as e:
            log.error("broadcast error: %s" % e)
            raise e

    def pubsubSignal(self, sig):
        """
        Process a notification from the block explorer.

        Arg:
            sig (dict or string): The block explorer's notification, decoded.
        """
        if sig == WS_DONE:
            return
        sigType = sig["event"]
        try:
            if sigType == "address":
                msg = sig["message"]
                addr = msg["address"]
                log.debug("signal received for %s" % msg["address"])
                receiver = self.addrSubscribers.get(addr)
                if not receiver:
                    log.error("no receiver registered for address %s", addr)
                    return
                receiver(addr, msg["transaction"])
            elif sigType == "newblock":
                self.tipHeight = sig["message"]["block"]["height"]
                for receiver in self.blockSubscribers:
                    receiver(sig)
            elif sigType == "subscribeResp":
                # should check for error.
                pass
            elif sigType == "ping":
                # nothing to do here right now. May want to implement a
                # auto-reconnect using this signal.
                pass
            else:
                raise DecredError("unknown signal %s" % repr(sigType))
        except Exception as e:
            log.error("failed to process pubsub message: %s" % formatTraceback(e))

    def changeScript(self, changeAddress):
        """
        Get a pubkey script for a change output.
        """
        return txscript.makePayToAddrScript(changeAddress, self.netParams)

    def approveUTXO(self, utxo):
        # If the UTXO appears unconfirmed, see if it can be confirmed.
        if utxo.maturity and self.tipHeight < utxo.maturity:
            return False
        if utxo.isTicket():
            # Temporary until revocations implemented.
            return False
        return True

    def confirmUTXO(self, utxo, block=None, tx=None):
        if not tx:
            # No tx found is an issue, so pass the exception.
            tx = self.tx(utxo.txid)
        try:
            # No block found is not an error.
            if not block:
                block = self.blockForTx(utxo.txid)
            utxo.confirm(block, tx, self.netParams)
            return True
        except Exception:
            pass
        return False

    def sendOutputs(self, outputs, keysource, utxosource, feeRate=None):
        """
        Send the `TxOut`s to the address.

        mostly based on:
          (dcrwallet/wallet/txauthor).NewUnsignedTransaction
          (dcrwallet/wallet).txToOutputsInternal
          (dcrwallet/wallet/txauthor).AddAllInputScripts

        Args:
            outputs list(TxOut): The transaction outputs to send.
            keysource func(str) -> PrivateKey: A function that returns the
                private key for an address.
            utxosource func(int, func(UTXO) -> bool) -> (list(UTXO), bool):
                A function that takes an amount in atoms, and an optional
                filtering function. utxosource returns a list of UTXOs that sum
                to >= the amount, and a bool that states whether the funds are
                sufficient to complete the transaction. If the filtering
                function is provided, UTXOs for which the  function return a
                falsey value will not be included in the returned UTXO list.

        Returns:
            newTx MsgTx: The sent transaction.
            utxos list(UTXO): The spent UTXOs.
            newUTXOs list(UTXO): Length 1 array containing the new change UTXO.
        """
        total = 0
        inputs = []
        scripts = []
        scriptSizes = []

        changeAddress = keysource.internal()
        changeScript = self.changeScript(changeAddress)
        changeScriptVersion = txscript.DefaultScriptVersion
        changeScriptSize = txscript.P2PKHPkScriptSize

        relayFeePerKb = feeRate * 1e3 if feeRate else self.relayFee()
        for (i, txout) in enumerate(outputs):
            checkOutput(txout, relayFeePerKb)

        signedSize = txscript.estimateSerializeSize(
            [txscript.RedeemP2PKHSigScriptSize], outputs, changeScriptSize
        )
        targetFee = txscript.calcMinRequiredTxRelayFee(relayFeePerKb, signedSize)
        targetAmount = sum(txo.value for txo in outputs)

        while True:
            utxos, enough = utxosource(targetAmount + targetFee, self.approveUTXO)
            if not enough:
                raise InsufficientFundsError("insufficient funds")
            for utxo in utxos:
                tx = self.tx(utxo.txid)
                # header = self.blockHeaderByHeight(utxo["height"])
                txout = tx.txOut[utxo.vout]

                opCodeClass = txscript.getP2PKHOpCode(txout.pkScript)
                tree = (
                    wire.TxTreeRegular
                    if opCodeClass == txscript.opNonstake
                    else wire.TxTreeStake
                )
                op = msgtx.OutPoint(txHash=tx.cachedHash(), idx=utxo.vout, tree=tree)
                txIn = msgtx.TxIn(previousOutPoint=op, valueIn=txout.value)

                total += txout.value
                inputs.append(txIn)
                scripts.append(txout.pkScript)
                scriptSizes.append(txscript.spendScriptSize(txout.pkScript))

            signedSize = txscript.estimateSerializeSize(
                scriptSizes, outputs, changeScriptSize
            )
            requiredFee = txscript.calcMinRequiredTxRelayFee(relayFeePerKb, signedSize)
            remainingAmount = total - targetAmount
            if remainingAmount < requiredFee:
                targetFee = requiredFee
                continue

            newTx = msgtx.MsgTx(
                serType=wire.TxSerializeFull,
                version=txscript.generatedTxVersion,
                txIn=inputs,
                txOut=outputs,
                lockTime=0,
                expiry=0,
                cachedHash=None,
            )

            change = None
            newUTXOs = []
            changeVout = -1
            changeAmount = round(total - targetAmount - requiredFee)
            if changeAmount != 0 and not txscript.isDustAmount(
                changeAmount, changeScriptSize, relayFeePerKb
            ):
                if len(changeScript) > txscript.MaxScriptElementSize:
                    raise DecredError(
                        "script size exceed maximum bytes pushable to the stack"
                    )
                change = msgtx.TxOut(
                    value=changeAmount,
                    version=changeScriptVersion,
                    pkScript=changeScript,
                )
                changeVout = len(newTx.txOut)
                newTx.txOut.append(change)
            else:
                signedSize = txscript.estimateSerializeSize(scriptSizes, newTx.txOut, 0)

            # dcrwallet conditionally randomizes the change position here
            if len(newTx.txIn) != len(scripts):
                raise DecredError(
                    "tx.TxIn and prevPkScripts slices must have equal length"
                )

            # Sign the inputs
            for i, txin in enumerate(newTx.txIn):
                pkScript = scripts[i]
                sigScript = txin.signatureScript
                scriptClass, addrs, numAddrs = txscript.extractPkScriptAddrs(
                    0, pkScript, self.netParams
                )
                script = txscript.signTxOutput(
                    self.netParams,
                    newTx,
                    i,
                    pkScript,
                    txscript.SigHashAll,
                    keysource,
                    sigScript,
                    crypto.STEcdsaSecp256k1,
                )
                txin.signatureScript = script
            self.broadcast(newTx.txHex())
            if change:
                newUTXOs.append(
                    account.UTXO(
                        address=changeAddress,
                        txHash=newTx.cachedHash(),
                        vout=changeVout,
                        ts=int(time.time()),
                        scriptPubKey=changeScript,
                        satoshis=changeAmount,
                    )
                )

            return newTx, utxos, newUTXOs

    def purchaseTickets(self, keysource, utxosource, req):
        """
        Based on dcrwallet (*Wallet).purchaseTickets.
        purchaseTickets indicates to the wallet that a ticket should be
        purchased using any currently available funds. Also, when the spend
        limit in the request is greater than or equal to 0, tickets that cost
        more than that limit will return an error that not enough funds are
        available.

        Args:
            keysource account.KeySource: a source for private keys.
            utxosource func(int, filterFunc) -> (list(UTXO), bool): a source for
                UTXOs. The filterFunc is an optional function to filter UTXOs,
                and is of the form func(UTXO) -> bool.
            req account.TicketRequest: the ticket data.

        Returns:
            (splitTx, tickets) tuple: first element is the split transaction.
                Second is a list of generated tickets.
            splitSpent list(msgtx.TxOut): the outputs spent for the split
                transaction.
            internalOutputs list(msgtx.TxOut): new outputs that fund internal
                addresses.

        """
        self.updateTip()
        # account minConf is zero for regular outputs for now. Need to make that
        # adjustable.
        # if req.minConf < 0:
        #     raise DecredError("negative minconf")

        # Need a positive or zero expiry that is higher than the next block to
        # generate.
        if req.expiry < 0:
            raise DecredError("negative expiry")

        # Perform a sanity check on expiry.
        if req.expiry <= self.tipHeight + 1 and req.expiry > 0:
            raise DecredError("expiry height must be above next block height")

        # Fetch a new address for creating a split transaction. Then,
        # make a split transaction that contains exact outputs for use
        # in ticket generation. Cache its hash to use below when
        # generating a ticket. The account balance is checked first
        # in case there is not enough money to generate the split
        # even without fees.
        # TODO (copied from dcrwallet) This can still sometimes fail if the
        # split amount required plus fees for the split is larger than the
        # balance we have, wasting an address. In the future,
        # address this better and prevent address burning.

        # Calculate the current ticket price.
        ticketPrice = self.stakeDiff()

        # Ensure the ticket price does not exceed the spend limit if set.
        if req.spendLimit > 0 and ticketPrice > req.spendLimit:
            raise DecredError(
                "ticket price %f above spend limit %f" % (ticketPrice, req.spendLimit)
            )

        # Check that pool fees is zero, which will result in invalid zero-valued
        # outputs.
        if req.poolFees == 0:
            raise DecredError("no pool fee specified")

        stakeSubmissionPkScriptSize = 0

        # Check the pool address from the request.
        if not req.poolAddress:
            raise DecredError("no pool address specified. solo voting not supported")

        poolAddress = addrlib.decodeAddress(req.poolAddress, self.netParams)

        # Check the passed address from the request.
        if not req.votingAddress:
            raise DecredError("voting address not set in purchaseTickets request")

        # decode the string addresses. This is the P2SH multi-sig script
        # address, not the wallets voting address, which is only one of the two
        # pubkeys included in the redeem P2SH script.
        votingAddress = addrlib.decodeAddress(req.votingAddress, self.netParams)

        # The stake submission pkScript is tagged by an OP_SSTX.
        if isinstance(votingAddress, addrlib.AddressScriptHash):
            stakeSubmissionPkScriptSize = txscript.P2SHPkScriptSize + 1
        elif (
            isinstance(votingAddress, addrlib.AddressPubKeyHash)
            and votingAddress.sigType == crypto.STEcdsaSecp256k1
        ):
            stakeSubmissionPkScriptSize = txscript.P2PKHPkScriptSize + 1
        else:
            raise DecredError(
                "unsupported voting address type %s" % votingAddress.__class__.__name__
            )

        ticketFeeIncrement = req.ticketFee
        if ticketFeeIncrement == 0:
            ticketFeeIncrement = self.relayFee()

        # Make sure that we have enough funds. Calculate different
        # ticket required amounts depending on whether or not a
        # pool output is needed. If the ticket fee increment is
        # unset in the request, use the global ticket fee increment.

        # A pool ticket has:
        #   - two inputs redeeming a P2PKH for the worst case size
        #   - a P2PKH or P2SH stake submission output
        #   - two ticket commitment outputs
        #   - two OP_SSTXCHANGE tagged P2PKH or P2SH change outputs
        #
        #   NB: The wallet currently only supports P2PKH change addresses.
        #   The network supports both P2PKH and P2SH change addresses however.
        inSizes = [txscript.RedeemP2PKHSigScriptSize, txscript.RedeemP2PKHSigScriptSize]
        outSizes = [
            stakeSubmissionPkScriptSize,
            txscript.TicketCommitmentScriptSize,
            txscript.TicketCommitmentScriptSize,
            txscript.P2PKHPkScriptSize + 1,
            txscript.P2PKHPkScriptSize + 1,
        ]
        estSize = txscript.estimateSerializeSizeFromScriptSizes(inSizes, outSizes, 0)

        ticketFee = txscript.calcMinRequiredTxRelayFee(ticketFeeIncrement, estSize)
        neededPerTicket = ticketFee + ticketPrice

        # If we need to calculate the amount for a pool fee percentage,
        # do so now.
        poolFeeAmt = txscript.stakePoolTicketFee(
            ticketPrice,
            ticketFee,
            self.tipHeight,
            req.poolFees,
            self.subsidyCache,
            self.netParams,
        )

        # Fetch the single use split address to break tickets into, to
        # immediately be consumed as tickets.
        splitTxAddr = keysource.internal()

        # TODO: Don't reuse addresses
        # TODO: Consider wrapping. see dcrwallet implementation.
        splitPkScript = txscript.makePayToAddrScript(splitTxAddr, self.netParams)

        # Create the split transaction by using txToOutputs. This varies
        # based upon whether or not the user is using a stake pool or not.
        # For the default stake pool implementation, the user pays out the
        # first ticket commitment of a smaller amount to the pool, while
        # paying themselves with the larger ticket commitment.
        splitOuts = []
        for i in range(req.count):
            userAmt = neededPerTicket - poolFeeAmt
            poolAmt = poolFeeAmt

            # Pool amount.
            splitOuts.append(msgtx.TxOut(value=poolAmt, pkScript=splitPkScript,))

            # User amount.
            splitOuts.append(msgtx.TxOut(value=userAmt, pkScript=splitPkScript,))

        txFeeIncrement = req.txFee
        if txFeeIncrement == 0:
            txFeeIncrement = self.relayFee()

        # Send the split transaction.
        # sendOutputs takes the fee rate in atoms/byte
        splitTx, splitSpent, internalOutputs = self.sendOutputs(
            splitOuts, keysource, utxosource, int(txFeeIncrement / 1000)
        )

        # Generate the tickets individually.
        tickets = []

        for i in range(req.count):
            # Generate the extended outpoints that we need to use for ticket
            # inputs. There are two inputs for pool tickets corresponding to the
            # fees and the user subsidy, while user-handled tickets have only one
            # input.
            poolIdx = i * 2
            poolTxOut = splitTx.txOut[poolIdx]
            userIdx = i * 2 + 1
            txOut = splitTx.txOut[userIdx]

            eopPool = txscript.ExtendedOutPoint(
                op=msgtx.OutPoint(
                    txHash=splitTx.cachedHash(), idx=poolIdx, tree=wire.TxTreeRegular,
                ),
                amt=poolTxOut.value,
                pkScript=poolTxOut.pkScript,
            )
            eop = txscript.ExtendedOutPoint(
                op=msgtx.OutPoint(
                    txHash=splitTx.cachedHash(), idx=userIdx, tree=wire.TxTreeRegular,
                ),
                amt=txOut.value,
                pkScript=txOut.pkScript,
            )

            addrSubsidy = addrlib.decodeAddress(keysource.internal(), self.netParams)

            # Generate the ticket msgTx and sign it.
            ticket = txscript.makeTicket(
                self.netParams,
                eopPool,
                eop,
                votingAddress,
                addrSubsidy,
                ticketPrice,
                poolAddress,
            )
            forSigning = []
            eopPoolCredit = txscript.Credit(
                op=eopPool.op,
                blockMeta=None,
                amount=eopPool.amt,
                pkScript=eopPool.pkScript,
                received=int(time.time()),
                fromCoinBase=False,
            )
            forSigning.append(eopPoolCredit)
            eopCredit = txscript.Credit(
                op=eop.op,
                blockMeta=None,
                amount=eop.amt,
                pkScript=eop.pkScript,
                received=int(time.time()),
                fromCoinBase=False,
            )
            forSigning.append(eopCredit)

            # Set the expiry.
            ticket.expiry = req.expiry

            txscript.signP2PKHMsgTx(ticket, forSigning, keysource, self.netParams)

            # dcrwallet actually runs the pk scripts through the script
            # Engine as another validation step. Engine not implemented in
            # Python yet.
            # validateMsgTx(op, ticket, creditScripts(forSigning))

            # For now, don't allow any high fees (> 1000x default). Could later
            # be a property of the account.
            if txscript.paysHighFees(eop.amt, ticket):
                raise DecredError("high fees detected")

            self.broadcast(ticket.txHex())
            tickets.append(ticket)
            log.info("published ticket %s" % ticket.txid())

            # Add a UTXO to the internal outputs list.
            txOut = ticket.txOut[0]
            internalOutputs.append(
                account.UTXO(
                    address=votingAddress.string(),
                    txHash=ticket.cachedHash(),
                    vout=0,  # sstx is output 0
                    ts=int(time.time()),
                    scriptPubKey=txOut.pkScript,
                    satoshis=txOut.value,
                )
            )
        return (splitTx, tickets), splitSpent, internalOutputs

    def revokeTicket(self, tx, keysource, redeemScript):
        """
        Revoke a ticket by signing the supplied redeem script and broadcasting
        the raw transaction.

        Args:
            tx (object): the msgTx of the ticket purchase.
            keysource (object): a KeySource object that holds a function to get
                the private key used for signing.
            redeemScript (byte-like): the 1-of-2 multisig script that delegates
                voting rights for the ticket.

        Returns:
            MsgTx: the signed revocation.
        """

        revocation = txscript.makeRevocation(tx, self.relayFee())

        signedScript = txscript.signTxOutput(
            self.netParams,
            revocation,
            0,
            redeemScript,
            txscript.SigHashAll,
            keysource,
            revocation.txIn[0].signatureScript,
            crypto.STEcdsaSecp256k1,
        )

        # Append the redeem script to the signature
        signedScript += txscript.addData(redeemScript)
        revocation.txIn[0].signatureScript = signedScript

        self.broadcast(revocation.txHex())

        log.info("published revocation %s" % revocation.txid())
        return revocation
