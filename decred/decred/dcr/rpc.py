"""
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details
"""

import base64
import json
import queue
import ssl
import types

from decred import DecredError
from decred.crypto.opcode import OP_SSRTX
from decred.util import tinyhttp, ws
from decred.util.encode import ByteArray
from decred.util.helpers import getLogger, makeWebsocketURL

from . import agenda, txscript
from .wire.msgblock import BlockHeader
from .wire.msgtx import MsgTx, TxOut, TxTreeStake


log = getLogger("RPC")


def coinify(atoms):
    """
    Convert the smallest unit of a coin into its coin value.

    Args:
        atoms (int): 1e8 division of a coin.

    Returns:
        float: The coin value.
    """
    return round(atoms / 1e8, 8)


def stringify(thing):
    """
    Helper method to convert reversed bytes or iterable objects of reversed
    bytes to hex strings. If it is already a string, it is untouched.

    Args:
        thing (iterable of str or ByteArray): The thing to convert to strings.

    Returns:
        list(str) or str: The thing converted to a hex encoded str.
    """

    if isinstance(thing, types.GeneratorType):
        return (stringify(t) for t in thing)
    if isinstance(thing, tuple):
        return tuple(stringify(t) for t in thing)
    if isinstance(thing, set):
        return set(stringify(t) for t in thing)
    if isinstance(thing, list):
        return list(stringify(t) for t in thing)
    if isinstance(thing, ByteArray):
        return reversed(thing).hex()
    return thing


class Response:
    """Parses a JSON-RPC 2.0 response."""

    def __init__(self, jsonRep):
        """
        Args:
            jsonRep (str or dict): The raw result from the server.
        """
        msg = json.loads(jsonRep) if isinstance(jsonRep, str) else jsonRep
        self.id = msg.get("id")
        self.result = msg.get("result")
        self.error = msg.get("error")


class Request:
    """A JSON-RPC 2.0 request."""

    def __init__(self, reqID, method, params):
        """
        Args:
            reqID (int): The request ID.
            method (str): The JSON-RPC method.
            params (list): JSON-serializable parameters.
        """
        self.id = reqID
        self.method = method
        self.params = params

    def dict(self):
        """
        Dump the Request as a Python dictionary.

        Returns:
            dict: The Request encoded as a Python dictionary.
        """
        return {
            "jsonrpc": "2.0",
            "id": self.id,
            "method": self.method,
            "params": self.params,
        }

    def json(self):
        """
        Dump the request as a JSON-formatted string.

        Returns:
            str: The Request encoded as a JSON string.
        """
        return json.dumps(self.dict())


class Client:
    """
    The Client communicates with the blockchain RPC API.
    """

    nextRequestID = 0

    def __init__(self, url, user, pw, cert=None):
        """
        Args:
            url (str): The RPC address.
            user (str): The rpcuser set in the dcrd configuration.
            pw (str): The rpcpass set in the dcrd configuration.
            cert (str): Optional. The location of the server's TLS.
                certificate.
        """
        authString = str(base64.b64encode("{0}:{1}".format(user, pw).encode()))[2:-1]
        self.headers = {
            "content-type": "application/json",
            "Authorization": "Basic " + (authString),
        }
        self.url = url
        self.cert = cert
        self.sslContext = None
        if cert:
            self.sslContext = ssl.SSLContext()
            self.sslContext.load_verify_locations(cert)

    def jsonRequest(self, method, params):
        """
        Create a Request with a unique ID.

        Args:
            method (str): The JSON-RPC method.
            params (list): JSON-serializable parameters.

        Returns:
            Request: The request.
        """
        reqID = self.nextRequestID
        self.nextRequestID = reqID + 1
        return Request(reqID, method, params)

    def call(self, method, *params):
        """
        Call the specified remote method with the specified list of parameters.

        Args:
            method (str): The JSON-RPC method.
            params (list): JSON-serializable parameters.

        Returns:
            dict: The response's result.
        """
        req = self.jsonRequest(method, params)
        rawRes = tinyhttp.post(
            self.url, req.dict(), headers=self.headers, context=self.sslContext
        )
        resp = Response(rawRes)
        if resp.error:
            raise DecredError(f"{method} error: {resp.error}")
        return resp.result

    def addNode(self, addr, subCmd):
        """
        Attempts to add or remove a persistent peer.

        Args:
            addr (str): IP address and port of the peer to operate on
            subCmd (str): 'add' to add a persistent peer, 'remove' to remove a
                persistent peer, or 'onetry' to try a single connection to a peer
        """
        self.call("addnode", addr, subCmd)

    def createRawSSRTx(self, ticket, relayFee=None):
        """
        Returns a new unsigned transaction revoking the ticket.

        Args:
            ticket (msgTx.MsgTx): The ticket to revoke.
            fee (int): Optional. Default=None. The fee to apply to the
                revocation in atoms/kb.

        Returns:
            MstTx.msgtx: The revocation.
        """
        fee = None
        if relayFee:
            outs = []
            # Parse the ticket purchase transaction to determine the required output
            # destinations for vote rewards or revocations.
            (
                ticketPayKinds,
                ticketHash160s,
                ticketValues,
                _,
                _,
                _,
            ) = txscript.sstxStakeOutputInfo(ticket.txOut)

            # Calculate the output values for the revocation.  Revocations do not
            # contain any subsidy.
            values = txscript.calculateRewards(ticketValues, ticket.txOut[0].value, 0)

            # All remaining outputs pay to the output destinations and amounts tagged
            # by the ticket purchase.
            for i in range(len(ticketHash160s)):
                scriptFn = txscript.payToStakePKHScript
                # P2SH
                if ticketPayKinds[i]:
                    scriptFn = txscript.payToStakeSHScript
                script = scriptFn(ticketHash160s[i], OP_SSRTX)
                outs.append(TxOut(values[i], script))

            # Calculate the estimated signed serialize size.
            scriptSizes = [txscript.RedeemP2SHSigScriptSize]
            sizeEstimate = txscript.estimateSerializeSize(scriptSizes, outs, 0)
            fee = txscript.calcMinRequiredTxRelayFee(relayFee, sizeEstimate)
            # dcrd takes amounts in coins
            fee = coinify(fee)

        vOuts = [
            {
                "txid": ticket.txid(),
                # dcrd takes amounts in coins
                "amount": coinify(ticket.txOut[0].value),
                "vout": 0,
                "tree": TxTreeStake,
            }
        ]
        res = self.call("createrawssrtx", vOuts, *([fee] if fee else []))
        return MsgTx.deserialize(ByteArray(res))

    def createRawSSTx(self, inputs, amount, cOuts):
        """
        Returns a new transaction spending the provided inputs and sending to
        the provided addresses. The transaction inputs are not signed in the
        created transaction. The signrawtransaction RPC command provided by
        wallet must be used to sign the resulting transaction.

        Args:
            inputs (list(UTXO)): The inputs to the transaction.
            amount (dict[str]float): Dictionary with the destination addresses
                as keys and amounts in atoms as values.
            cOuts (list(COut)): Array of sstx commit outs to use.

        Result:
            msgtx.MsgTx: The serialized transaction
        """
        vOuts = [
            {
                "txid": reversed(utxo.txHash).hex(),
                "vout": utxo.vout,
                "tree": txscript.scriptTree(utxo.scriptClass),
                "amt": utxo.satoshis,
            }
            for utxo in inputs
        ]
        cs = [cOut.toJSON() for cOut in cOuts]
        res = self.call("createrawsstx", vOuts, amount, cs)
        ticketPurchase = MsgTx.deserialize(ByteArray(res))
        # TxIn.valueIn are not set until dcrd version 1.6.
        for i, vOut in enumerate(vOuts):
            ticketPurchase.txIn[i].valueIn = vOut["amt"]
        return ticketPurchase

    def createRawTransaction(self, inputs, amounts, locktime=None, expiry=None):
        """
        Returns a new transaction spending the provided inputs and sending to
        the provided addresses. The transaction inputs are not signed in the
        created transaction. The signrawtransaction RPC command provided by
        wallet must be used to sign the resulting transaction.

        Args:
            inputs (list(UTXO)): The inputs to the transaction.
            amounts (dict[str]int) JSON-derived dict with the destination addresses
                as keys and amounts as values in atoms.
            locktime (int): Optional. Default=None. Locktime value; a non-zero
                value will also locktime-activate the inputs.
            expiry (int) Optional. Default=None. Expiry value. a non-zero value
                when the transaction expires.

        Result:
            msgtx.MsgTx: The serialized transaction
        """
        vOuts = [
            {
                "txid": reversed(utxo.txHash).hex(),
                "vout": utxo.vout,
                "tree": txscript.scriptTree(utxo.scriptClass),
                # dcrd takes amounts in coins
                "amount": coinify(utxo.satoshis),
            }
            for utxo in inputs
        ]
        # dcrd takes amounts in coins
        for k, v in amounts.items():
            amounts[k] = coinify(v)
        res = self.call(
            "createrawtransaction",
            vOuts,
            amounts,
            *([locktime] if locktime else []),
            *([expiry] if expiry and locktime else []),
        )
        return MsgTx.deserialize(ByteArray(res))

    def debugLevel(self, levelSpec):
        """
        Dynamically changes the debug logging level. The levelspec can be
        either a debug level or of the form:
        <subsystem>=<level>,<subsystem2>=<level2>,...
        The valid debug levels are trace, debug, info, warn, error, and critical.
        The valid subsystems are AMGR, ADXR, BCDB, BMGR, DCRD, CHAN, DISC, PEER,
        RPCS, SCRP, SRVR, and TXMP. Finally, the keyword 'show' will return a
        list of the available subsystems.

        Args:
            levelSpec (str): The debug level(s) to use or the keyword 'show'.

        Returns:
            str: The list of subsystems if levelSpec == 'show',
                else the string 'Done.'.
        """
        return self.call("debuglevel", levelSpec)

    def decodeRawTransaction(self, tx):
        """
        Returns the transaction decoded as a RawTransactionResult.

        Args:
            tx (msgtx.MsgTx): The transaction.

        Returns:
            RawTransactionResult: The decoded transaction.
        """
        return RawTransactionResult.parse(self.call("decoderawtransaction", tx.txHex()))

    def decodeScript(self, script, version=0):
        """
        Information about the provided hex-encoded script.

        Args:
            script (ByteArray): The script.
            version (int): Optional. Default=0 The script version.

        Returns:
            DecodeScriptResult: The script, decoded.
        """
        return DecodeScriptResult.parse(
            self.call("decodescript", script.hex(), version)
        )

    def estimateFee(self):
        """
        Returns the estimated fee in atoms/kb.

        Returns:
            int: Estimated fee in atoms/kb.
        """
        return int(self.call("estimatefee", 0) * 1e8)

    def estimateSmartFee(self, confirmations):
        """
        Returns the estimated fee using the historical fee data in atoms/kb.

        Args:
            confirmations (int): Max 32. Estimate the fee rate a transaction requires so
                that it is mined in up to this number of blocks.

        Returns:
            int: Estimated fee rate in atoms/kb.
        """
        return int(self.call("estimatesmartfee", confirmations, "conservative") * 1e8)

    def estimateStakeDiff(self, tickets):
        """
        Estimate the next minimum, maximum, expected, and user-specified stake
        difficulty.

        Args:
            tickets (int): Use this number of new tickets in blocks
                to estimate the next difficulty.

        Returns:
            EstimateStakeDiffResult: The estimated difficulty.
        """
        return EstimateStakeDiffResult.parse(self.call("estimatestakediff", tickets))

    def existsAddress(self, address):
        """
        Test for the existence of the provided address.

        Args:
            address (str): The address to check.

        Returns:
            bool: True if address exists.
        """
        return self.call("existsaddress", address)

    def existsAddresses(self, addresses):
        """
        Test for the existence of the provided addresses in the blockchain or
            memory pool.

        Args:
            addresses (list(str)) The addresses to check.

        Returns:
            list(bool): Bool list showing if addresses exist or not.
        """
        mask = ByteArray(self.call("existsaddresses", addresses)).littleEndian().int()
        return [bool(mask & 1 << n) for n in range(len(addresses))]

    def existsExpiredTickets(self, txHashes):
        """
        Test for the existence of the provided tickets in the expired ticket map.

        Args:
            txHashes (list(ByteArray) or list(str)): Array of hashes to check.

        Returns:
            list(bool): Bool list showing if ticket exists in the expired ticket
                database or not.
        """
        mask = int(self.call("existsexpiredtickets", stringify(txHashes)), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def existsLiveTicket(self, txHash):
        """
        Test for the existence of the provided ticket

        Args:
            txHash (ByteArray or str): The ticket hash to check.

        Returns:
            bool: True if address exists in the live ticket database.
        """
        return self.call("existsliveticket", stringify(txHash))

    def existsLiveTickets(self, txHashes):
        """
        Test for the existence of the provided tickets in the live ticket map.

        Args:
            txHashes (list(ByteArray) or list(str)): Array of hashes to check.

        Returns:
            list(bool): Bool list showing if ticket exists in the live ticket
                database or not.
        """
        mask = int(self.call("existslivetickets", stringify(txHashes)), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def existsMempoolTxs(self, txHashes):
        """
        Test for the existence of the provided txs in the mempool.

        Args:
            txHashes (list(ByteArray) or list(str)): Array of hashes to check.

        Returns:
            list(bool): Bool list showing if txs exist in the mempool or not.
        """
        mask = int(self.call("existsmempooltxs", stringify(txHashes)), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def existsMissedTickets(self, txHashes):
        """
        Test for the existence of the provided tickets in the missed ticket map.

        Args:
            txHashes (list(ByteArray) or list(str)):Array of hashes to check.

        Returns:
            list(bool): Bool list showing if the ticket exists in the missed
                ticket database or not.
        """
        mask = int(self.call("existsmissedtickets", stringify(txHashes)), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def generate(self, numBlocks):
        """
        Generates a set number of blocks (simnet or regtest only) and returns a
        JSON array of their hashes.

        Args:
            numBlocks (int): Number of blocks to generate.

        Returns:
            list(ByteArray): The hashes, in order, of blocks generated by the call.
        """
        res = self.call("generate", numBlocks)
        return [reversed(ByteArray(h)) for h in res]

    def getAddedNodeInfo(self, dns, node=None):
        """
        Returns information about manually added (persistent) peers.

        Args:
            dns (bool): Specifies whether the returned data is a JSON-derived
                dict including DNS and connection information, or just a list of
                added peers.
            node (str): Optional. Default=None. Only return information about
                this specific peer instead of all added peers.

        Returns:
            list(str): List of added peers
        """
        res = self.call("getaddednodeinfo", dns, *([node] if node else []))
        return [GetAddedNodeInfoResult.parse(node) for node in res] if dns else res

    def getBestBlock(self):
        """
        Get the height of the current best block.

        Returns:
            GetBestBlockResult: The block data.
        """
        return GetBestBlockResult.parse(self.call("getbestblock"))

    def getBestBlockHash(self):
        """
        Returns the hash of the best (most recent) block in the longest block
        chain.

        Returns:
            ByteArray: The block hash
        """
        return reversed(ByteArray(self.call("getbestblockhash")))

    def getBlock(self, blockHash, verbose=True, verboseTx=False):
        """
        Returns information about a block given its hash.

        Args:
            blockHash (ByteArray or str): The hash of the block.
            verbose (bool): Optional. Default=True. Specifies the block is
                returned as a GetBlockVerboseResult instead of serialized bytes.
            verboseTx (bool): Optional. Default=False. Specifies that each
                transaction is returned as a RawTransactionResult and only
                applies if the verbose flag is true (dcrd extension).

        Returns:
            ByteArray or GetBlockVerboseResult: GetBlockVerboseResult if verbose
                else the bytes of the serialized block.
        """
        res = self.call("getblock", stringify(blockHash), verbose, verboseTx)
        return GetBlockVerboseResult.parse(res) if verbose else ByteArray(res)

    def getBlockchainInfo(self):
        """
        Get the blockchain info.

        Returns:
            GetBlockChainInfoResult: The blockchain info.
        """
        return GetBlockChainInfoResult.parse(self.call("getblockchaininfo"))

    def getBlockCount(self):
        """
        Returns the number of blocks in the longest block chain.

        Returns:
            int: The current block count.
        """
        return self.call("getblockcount")

    def getBlockHash(self, index):
        """
        Returns hash of the block in best block chain at the given height.

        Args:
            index (int): The block height.

        Returns:
            ByteArray: The block hash.
        """
        res = self.call("getblockhash", index)
        return reversed(ByteArray(res))

    def getBlockHeader(self, blockHash, verbose=True):
        """
        Returns information about a block header given its hash.

        Args:
            blockHash (ByteArray or str): The hash of the block.
            verbose (bool): Optional. Default=True. Specifies the block
                header is returned as a GetBlockHeaderVerboseResult instead of
                a msgblock.BlockHeader.

        Returns:
            GetBlockHeaderVerboseResult or msgblock.BlockHeader: The
                GetBlockHeaderVerboseResult if verbose or the BlockHeader
                otherwise.
        """
        res = self.call("getblockheader", stringify(blockHash), verbose)
        return (
            GetBlockHeaderVerboseResult.parse(res)
            if verbose
            else BlockHeader.btcDecode(ByteArray(res), 0)
        )

    def getBlockSubsidy(self, height, voters):
        """
        Returns information regarding subsidy amounts.

        Args:
            height (int): The block height.
            voters (int): The number of voters.

        Returns:
            GetBlockSubsidyResult: The subsidy amounts.
        """
        return GetBlockSubsidyResult.parse(self.call("getblocksubsidy", height, voters))

    def getCFilter(self, blockHash, filterType):
        """
        Returns the committed filter for a block

        Args:
            blockHash (ByteArray or str): The block hash of the filter being queried.
            filterType (str): The type of committed filter to return.

        Returns:
            ByteArray: The committed filter serialized with the N value.
        """
        res = self.call("getcfilter", stringify(blockHash), filterType)
        return ByteArray(res)

    def getCFilterHeader(self, blockHash, filterType):
        """
        Returns the filter header hash committing to all filters in the chain up
        through a block.

        Args:
            blockHash (ByteArray or str): The block hash of the filter header
                being queried.
            filterType (str): The type of committed filter to return the
                header commitment for.

        Returns:
            ByteArray: The filter header commitment hash.
        """
        res = self.call("getcfilterheader", stringify(blockHash), filterType)
        return ByteArray(res)

    def getCFilterV2(self, blockHash):
        """
        Returns the version 2 block filter for the given block along with a
            proof that can be used to prove the filter is committed to by the
            block header.

        Args:
            blockHash (ByteArray or str): The block hash of the filter to retrieve.

        Returns:
            GetCFilterV2Result: The version 2 block filter.
        """
        return GetCFilterV2Result.parse(self.call("getcfilterv2", stringify(blockHash)))

    def getChainTips(self):
        """
        Returns information about all known chain tips the in the block tree.

        The statuses in the result have the following meanings:
            active: The current best chain tip.
            invalid: The block or one of its ancestors is invalid.
            headers-only: The block or one of its ancestors does not have the
                full block data available which also means the block can't be
                validated or connected.
            valid-fork: The block is fully validated which implies it was
                probably part of the main chain at one point and was reorganized.
            valid-headers: The full block data is available and the header is
                valid, but the block was never validated which implies it was
                probably never part of the main chain.

        Returns:
            list(GetChainTipsResult): The tips.
        """
        return [GetChainTipsResult.parse(tip) for tip in self.call("getchaintips")]

    def getCoinSupply(self):
        """
        Returns current total coin supply in atoms.

        Returns:
            int: Current coin supply in atoms.
        """
        return self.call("getcoinsupply")

    def getConnectionCount(self):
        """
        Returns the number of active connections to other peers.

        Returns:
            int: The number of connections.
        """
        return self.call("getconnectioncount")

    def getCurrentNet(self):
        """
        Get Decred network the server is running on.

        Returns:
            int: The network identifier.
        """
        return self.call("getcurrentnet")

    def getDifficulty(self):
        """
        Returns the proof-of-work difficulty as a multiple of the minimum difficulty.

        Returns:
            float: The difficulty.
        """
        return self.call("getdifficulty")

    def getGenerate(self):
        """
        Returns if the server is set to generate coins (mine) or not.

        Returns:
            bool: True if mining, false if not.
        """
        return self.call("getgenerate")

    def getHashesPerSec(self):
        """
        Returns a recent hashes per second performance measurement while
        generating coins (mining).

        Returns:
            int: The number of hashes per second.
        """
        return self.call("gethashespersec")

    def getHeaders(self, blockLocators, hashStop):
        """
        Returns block headers starting with the first known block hash from the
        request.

        Args:
            blockLocators (list(ByteArray)): Array of block locator hashes.
                Headers are returned starting from the first known hash in this
                list.
            hashStop (ByteArray): Block hash to stop including block headers for.
                Set to zero to get as many blocks as possible.

        Returns:
            list(msgblock.BlockHeader): Block headers of all located blocks,
                limited to some arbitrary maximum number of hashes (currently
                2000, which matches the wire protocol headers message, but this
                is not guaranteed).
        """
        res = self.call("getheaders", stringify(blockLocators), stringify(hashStop))[
            "headers"
        ]
        return [BlockHeader.btcDecode(ByteArray(header), 0) for header in res]

    def getInfo(self):
        """
        Returns various state info.

        Returns:
            InfoChainResult: Various state info.
        """
        return InfoChainResult.parse(self.call("getinfo"))

    def getMempoolInfo(self):
        """
        Returns memory pool information.

        Returns:
            GetMempoolInfoResult: The mempool information.
        """
        return GetMempoolInfoResult.parse(self.call("getmempoolinfo"))

    def getMiningInfo(self):
        """
        Returns mining-related information.

        Returns:
            GetMiningInfoResult: The minig information.
        """
        return GetMiningInfoResult.parse(self.call("getmininginfo"))

    def getNetTotals(self):
        """
        Returns network traffic statistics.

        Returns:
            GetNetTotalsResult: The network traffic stats.
        """
        return GetNetTotalsResult.parse(self.call("getnettotals"))

    def getNetworkHashPS(self, blocks=120, height=-1):
        """
        Returns the estimated network hashes per second for the block heights
        provided by the parameters.

        Args:
            blocks (int) Optional. Default=120. The number of blocks, or -1 for
                blocks since last difficulty change.
            height (int) Optional. Default=-1. Perform estimate ending with this
                height or -1 for current best chain block height.

        Returns:
            int: Estimated hashes per second.
        """
        return self.call("getnetworkhashps", blocks, height)

    def getNetworkInfo(self):
        """
        Returns network-related information.

        Returns:
            GetNetworkInfoResult: The network-related info.
        """
        return GetNetworkInfoResult.parse(self.call("getnetworkinfo"))

    def getPeerInfo(self):
        """
        Returns data about each connected network peer.

        Returns:
            list(GetPeerInfoResult): The peer info.
        """
        return [GetPeerInfoResult.parse(peer) for peer in self.call("getpeerinfo")]

    def getRawMempool(self, verbose=False, txtype=None):
        """
        Returns information about all of the transactions currently in the
        memory pool.

        Arg:
            verbose (bool) Optional. Default=false. Returns a list of
                GetRawMempoolVerboseResult when true or a list of transaction
                hashes when false.
            txtype (str) Optional. Default=None. Type of tx to return.
                (all/regular/tickets/votes/revocations).

        Returns:
            list(ByteArray) or dict[str]GetRawMempoolVerboseResult: Array of
                transaction hashes if not verbose. A dict of transaction hashes
                to GetRawMempoolVerboseResult if verbose.
        """
        res = self.call("getrawmempool", verbose, *([txtype] if txtype else []))
        return (
            {k: GetRawMempoolVerboseResult.parse(v) for k, v in res.items()}
            if verbose
            else [reversed(ByteArray(h)) for h in res]
        )

    def getRawTransaction(self, txHash, verbose=False):
        """
        Returns information about a transaction given its hash.

        Args:
            txHash (ByteArray or str): The hash of the transaction.
            verbose (bool): Optional. Default=False. Specifies the transaction is
                returned as a RawTransactionResult instead of a msgtx.MsgTx.

        Returns:
            msgtx.MsgTx or RawTransactionResult: RawTransactionResult if
                verbose, msgtx.MsgTx for the transaction if default.
        """
        verb = 1 if verbose else 0
        res = self.call("getrawtransaction", stringify(txHash), verb)
        return (
            RawTransactionResult.parse(res)
            if verbose
            else MsgTx.deserialize(ByteArray(res))
        )

    def getStakeDifficulty(self):
        """
        Returns the proof-of-stake difficulty.

        Returns:
            GetStakeDifficultyResult: The current and calculated next difficulty.
        """
        return GetStakeDifficultyResult.parse(self.call("getstakedifficulty"))

    def getStakeVersionInfo(self, count=1):
        """
        Returns stake version statistics for one or more stake version intervals.

        Args:
            count (int): Optional. Default=1. Number of intervals to return.

        Returns:
            GetStakeVersionInfoResult: The stake version statistics.
        """
        return GetStakeVersionInfoResult.parse(self.call("getstakeversioninfo", count))

    def getStakeVersions(self, blockHash, count):
        """
        Returns the stake versions statistics.

        Args:
            blockHash (ByteArray or str) The start block hash.
            count (int) The number of blocks that will be returned.

        Returns:
            list(GetStakeVersionsResult): Array of stake versions per block.
        """
        return [
            GetStakeVersionsResult.parse(ver)
            for ver in self.call("getstakeversions", stringify(blockHash), count)[
                "stakeversions"
            ]
        ]

    def getTicketPoolValue(self):
        """
        Return the current value of all locked funds in the ticket pool.

        Returns:
            float: Total value of ticket pool
        """
        return self.call("getticketpoolvalue")

    def getTxOut(self, txHash, vout, includeMempool=True):
        """
        Returns information about an unspent transaction output.

        Args:
            txHash (ByteArray or str): The hash of the transaction.
            vout (int): The index of the output.
            includeMempool (bool): Optional. Default=True. Include the mempool
                when true.

        Returns:
            GetTxOutResult: The utxo information.
        """
        return GetTxOutResult.parse(
            self.call("gettxout", stringify(txHash), vout, includeMempool)
        )

    def getVoteInfo(self, version):
        """
        Returns the vote info statistics.

        Args:
            version (int) The stake version.

        Returns:
            GetVoteInfoResult: The voting information.
        """
        return GetVoteInfoResult.parse(self.call("getvoteinfo", version))

    def getWork(self, data=None):
        """
        Returns formatted hash data to work on or checks and submits solved data.

        Args:
            data (ByteArray): Optional. Default=None. Data to check

        Returns:
            GetWorkResult or bool: If data is not provided, returns GetWorkResult,
                else returns whether or not the solved data is valid and was
                added to the chain.
        """
        res = self.call("getwork", *([data.hex()] if data else []))
        return res if data else GetWorkResult.parse(res)

    def help(self, command=None):
        """
        Returns a list of all commands or help for a specified command.

        Ars:
            command (str): Optional. Default=None. The command to retrieve help for.

        Returns:
            str: List of commands or help for specified command.
        """
        return self.call("help", *([command] if command else []))

    def liveTickets(self):
        """
        Returns live ticket hashes from the ticket database.

        Returns:
            list(ByteArray): List of live tickets.
        """
        res = self.call("livetickets")["tickets"]
        return [reversed(ByteArray(h)) for h in res]

    def missedTickets(self):
        """
        Returns missed ticket hashes from the ticket database.

        Returns:
            list(ByteArray): List of missed tickets.
        """
        res = self.call("missedtickets")["tickets"]
        return [reversed(ByteArray(h)) for h in res]

    def node(self, subcmd, target, connectSubCmd=None):
        """
        Attempts to add or remove a peer.

        Args:
            subcmd (str): 'disconnect' to remove all matching non-persistent
                peers, 'remove' to remove a persistent peer, or 'connect' to
                connect to a peer
            target (str): Either the IP address and port of the peer to
                operate on, or a valid peer ID.
            connectSubCmd (str): Optional. Default=None. 'perm' to make the
                connected peer a permanent one, 'temp' to try a single connect
                to a peer
        """
        self.call("node", subcmd, target, *([connectSubCmd] if connectSubCmd else []))

    def ping(self):
        """
        Queues a ping to be sent to each connected peer. Ping times are provided
            by getpeerinfo via the pingtime and pingwait fields.
        """
        self.call("ping")

    def searchRawTransactions(
        self,
        address,
        verbose=True,
        skip=0,
        count=100,
        vinextra=0,
        reverse=False,
        filterAddrs=None,
    ):
        """
        Returns raw data for transactions involving the passed address. Returned
        transactions are pulled from both the database, and transactions currently
        in the mempool. Transactions pulled from the mempool will have the
        'confirmations' field set to 0. Usage of this RPC requires the optional
        --addrindex flag to be activated, otherwise all responses will simply
        return with an error stating the address index has not yet been built.
        Similarly, until the address index has caught up with the current best
        height, all requests will return an error response in order to avoid
        serving stale data.

        Args:
            address (str): The Decred address to search for
            verbose (bool): Optional. default=True. Specifies the transaction
                is returned as a list of RawTransactionResult instead of
                hex-encoded strings.
            skip (int): Optional. Default=0. The number of leading transactions
                to leave out of the final response.
            count (int): Optional. Default=100. The maximum number of
                transactions to return.
            vinextra (int): Optional. Default=0. Specify that extra data from
                previous output will be returned in vin.
            reverse (bool): Optional. Default=False. Specifies that the
                transactions should be returned in reverse chronological order.
            filterAddrs (list(str)): Optional. Default=[]. Only inputs or
                outputs with matching address will be returned.

        Returns:
            list(RawTransactionResult): The RawTransactionResults.
        """
        verb = 1 if verbose else 0
        res = self.call(
            "searchrawtransactions",
            address,
            verb,
            skip,
            count,
            vinextra,
            reverse,
            filterAddrs if filterAddrs else [],
        )
        return (
            [RawTransactionResult.parse(rawTx) for rawTx in res]
            if verbose
            else [MsgTx.deserialize(ByteArray(rawTx)) for rawTx in res]
        )

    def sendRawTransaction(self, msgTx, allowHighFees=False):
        """
        Submits the transaction to the local peer and relays it to the network.

        Args:
            msgTx (object): msgtx.MsgTx signed transaction.
            allowHighFees (bool): Optional. Default=False. Whether or not to
                allow insanely high fees (dcrd does not yet implement this
                parameter, so it has no effect).

        Returns:
            ByteArray: The hash of the transaction.
        """
        txid = self.call("sendrawtransaction", msgTx.txHex(), allowHighFees)
        return reversed(ByteArray(txid))

    def setGenerate(self, generate, numCPUs=-1):
        """
        Set the server to generate coins (mine) or not.

        Args:
            generate (bool): Use True to enable generation, False to disable it.
            numCPUs (int): Optional. Default=-1. The number of processors
                (cores) to limit generation to or -1 for default.
        """
        self.call("setgenerate", generate, numCPUs)

    def stop(self):
        """
        Shutdown dcrd.

        Returns:
            str: 'dcrd stopping.'
        """
        return self.call("stop")

    def submitBlock(self, block, options=None):
        """
        Attempts to submit a new serialized block to the network.

        Args:
            block (ByteArray): The block.
            options: Optional. Default={}. This parameter is currently ignored.

        Returns:
            str: The reason the block was rejected if rejected or None.
        """
        return self.call("submitblock", block.hex(), options if options else {})

    def ticketFeeInfo(self, blocks=0, windows=0):
        """
        Get various information about ticket fees from the mempool, blocks, and
        difficulty windows (units: DCR/kB).

        Args:
            blocks (int): Optional. Default=0. The number of blocks, starting from
                the chain tip and descending, to return fee information about.
            windows (int): Optional. Default=0. The number of difficulty windows
                to return ticket fee information about.

        Returns:
            TicketFeeInfoResult: The ticket fee info.
        """
        return TicketFeeInfoResult.parse(self.call("ticketfeeinfo", blocks, windows))

    def ticketsForAddress(self, addr):
        """
        Request all the tickets for an address.

        Args:
            addr (str): Address to look for.

        Returns:
            list(ByteArray): Hashed tickets owned by the specified address.
        """
        res = self.call("ticketsforaddress", addr)["tickets"]
        return [reversed(ByteArray(h)) for h in res]

    def ticketVWAP(self, start=None, end=None):
        """
        Calculate the volume weighted average price of tickets for a range of
        blocks (default: full PoS difficulty adjustment depth).

        Args:
            start (int): Optional. Default=None. The start height to begin
                calculating the VWAP from.
            end (int): Optional. Default=None. The end height to begin
                calculating the VWAP from.

        Returns:
            float: The volume weighted average price.
        """
        return self.call(
            "ticketvwap", *([start] if start else []), *([end] if start and end else [])
        )

    def txFeeInfo(self, blocks=0, rangeStart=0, rangeEnd=0):
        """
        Get various information about regular transaction fees from the mempool,
        blocks, and difficulty windows.

        Args:
            blocks (int): Optional. Default=0. The number of blocks to calculate
                transaction fees for, starting from the end of the tip moving backwards.
            rangeStart (int): Optional. Default=0. The start height of the block
                range to calculate transaction fees for.
            rangeEnd (int): Optional. Default=0. The end height of the block
                range to calculate transaction fees for.

        Returns:
            TxFeeInfoResult: The tx fee info.
        """
        return TxFeeInfoResult.parse(
            self.call("txfeeinfo", blocks, rangeStart, rangeEnd)
        )

    def validateAddress(self, addr):
        """
        Validate an address.

        Args:
            addr (str): The address to validate.

        Returns:
            ValidateAddressChainResult: Whether the address can be verified.
        """
        return ValidateAddressChainResult.parse(self.call("validateaddress", addr))

    def verifyChain(self):
        """
        Verify the block chain database.

        Returns:
            bool: Whether the database can be verified.
        """
        return self.call("verifychain")

    def verifyMessage(self, addr, sig, message):
        """
        Verify that a message was signed by the private key belonging to addr.

        Args:
            addr (str): The address used to sign.
            sig (str): The signed message.
            message (str): The message.

        Returns:
            bool: Whether the message could be verified.
        """
        return self.call("verifymessage", addr, sig, message)

    def version(self):
        """
        Get the dcrd and dcrdjsonrpcapi version info.

        Returns:
            dict[str]VersionResult: dcrd's version info with keys "dcrd" and
                "dcrdjsonrpcapi".
        """
        return {k: VersionResult.parse(v) for k, v in self.call("version").items()}


class COut:
    """
    Models data used when sending a createRawSSTx. Contains an sstxcommitment output.
    """

    def __init__(
        self, addr, commitAmt, changeAddr, changeAmt,
    ):
        """
        Args:
            addr (str): Address to send sstx commit.
            commitAmt (int): Amount to commit.
            changeAddr (str): Address for change.
            changeAmt (int): Amount for change.
        """
        self.addr = addr
        self.commitAmt = commitAmt
        self.changeAddr = changeAddr
        self.changeAmt = changeAmt

    def toJSON(self):
        """
        Encode the COuts to JSON.

        Returns:
            JSON: The encoded couts.
        """
        return {
            "addr": self.addr,
            "commitamt": self.commitAmt,
            "changeaddr": self.changeAddr,
            "changeamt": self.changeAmt,
        }


class DecodeScriptResult:
    """
    Models data returned by the decodeScript command.
    """

    def __init__(
        self, asm, scriptType, reqSigs=None, addresses=None, p2sh=None,
    ):
        """

        Args:
            asm (str): Disassembly of the script.
            type (str): The type of the script (e.g. 'pubkeyhash').
            reqSigs (int): The number of required signatures or None.
            addresses (list(str)): The Decred addresses associated with this
                script or None.
            p2sh (str): The script hash for use in pay-to-script-hash transactions
                or None (only present if the provided redeem script is not already
                a pay-to-script-hash script).
        """
        self.asm = asm
        self.type = scriptType
        self.reqSigs = reqSigs
        self.addresses = addresses if addresses else []
        self.p2sh = p2sh

    @staticmethod
    def parse(obj):
        """
        Parse the DecodeScriptResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            DecodeScriptResult: The DecodeScriptResult.
        """
        return DecodeScriptResult(
            asm=obj["asm"],
            scriptType=obj["type"],
            reqSigs=obj.get("reqSigs"),
            addresses=[addr for addr in obj.get("addresses", [])],
            p2sh=obj.get("p2sh"),
        )


class EstimateStakeDiffResult:
    """
    Models the data returned by the estimateStakeDiff command.
    """

    def __init__(
        self, diffMin, diffMax, expected, user=None,
    ):
        """
        Args:
            diffMin (float): Minimum estimate for stake difficulty.
            diffMax (float): Maximum estimate for stake difficulty.
            expected (float): Expected estimate for stake difficulty.
            user (float): Estimate for stake difficulty with the passed user
                amount of tickets.
        """
        self.diffMin = diffMin
        self.diffMax = diffMax
        self.expected = expected
        self.user = user

    @staticmethod
    def parse(obj):
        """
        Parse the EstimateStakeDiffResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            EstimateStakeDiffResult: The EstimateStakeDiffResult.
        """
        return EstimateStakeDiffResult(
            diffMin=obj["min"],
            diffMax=obj["max"],
            expected=obj["expected"],
            user=obj.get("user"),
        )


class GetBlockVerboseResult:
    """
    Models data returned by the getBlock command.
    """

    def __init__(
        self,
        blockHash,
        confirmations,
        size,
        height,
        version,
        merkleRoot,
        stakeRoot,
        time,
        nonce,
        voteBits,
        finalState,
        voters,
        freshStake,
        revocations,
        poolSize,
        bits,
        sBits,
        extraData,
        stakeVersion,
        difficulty,
        chainWork,
        previousHash,
        nextHash=None,
        txHash=None,
        rawTx=None,
        sTxHash=None,
        rawSTx=None,
    ):
        """
        Args:
            blockHash (ByteArray): The hash of the block (same as provided).
            confirmations (int): The number of confirmations.
            size (int): The size of the block.
            height (int): The height of the block in the block chain.
            version (int): The block version.
            merkleRoot (ByteArray): Root hash of the merkle tree.
            stakeRoot (ByteArray): The block's sstx hashes the were included.
            time (int): The block time in seconds since 1 Jan 1970 GMT.
            nonce (int): The block nonce.
            voteBits (int): The block's voting results.
            finalState (ByteArray): The block's finalstate.
            voters (int): The number votes in the block.
            freshStake (int): The number of new tickets in the block.
            revocations (int): The number of revocations in the block.
            poolSize (int): The size of the live ticket pool.
            bits (ByteArray): The bits which represent the block difficulty.
            sBits (float): The stake difficulty of theblock.
            extraData (ByteArray): Extra data field for the requested block.
            stakeVersion (ByteArray): Stake Version of the block.
            difficulty (float): The proof-of-work difficulty as a multiple of
                the minimum difficulty.
            chainWork (ByteArray): The total number of hashes expected to produce
                the chain up to the block.
            previousHash (ByteArray): The hash of the previous block.
            nextHash (ByteArray): The hash of the next block (only if there is one).
            txHash (list(ByteArray)): The transaction (only when verboseTx=false).
            rawTx (list(RawTransactionResult)): The transactions as JSON-derived
                dicts (only when verboseTx=true).
            sTxHash (list(ByteArray)): The block's sstx hashes that were included (only
                when verboseTx=false).
            rawSTx (list(RawTransactionResult)): The block's raw sstx hashes
                that were included (only when verboseTx=true).
        """
        self.blockHash = blockHash
        self.confirmations = confirmations
        self.size = size
        self.height = height
        self.version = version
        self.merkleRoot = merkleRoot
        self.stakeRoot = stakeRoot
        self.time = time
        self.nonce = nonce
        self.voteBits = voteBits
        self.finalState = finalState
        self.voters = voters
        self.freshStake = freshStake
        self.revocations = revocations
        self.poolSize = poolSize
        self.bits = bits
        self.sBits = sBits
        self.extraData = extraData
        self.stakeVersion = stakeVersion
        self.difficulty = difficulty
        self.chainWork = chainWork
        self.previousHash = previousHash
        self.nextHash = nextHash
        self.txHash = txHash if txHash else []
        self.rawTx = rawTx if rawTx else []
        self.sTxHash = sTxHash if sTxHash else []
        self.rawSTx = rawSTx if rawSTx else []

    @staticmethod
    def parse(obj):
        """
        Parse the GetBlockVerboseResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetBlockVerboseResult: The GetBlockVerboseResult.
        """
        return GetBlockVerboseResult(
            blockHash=reversed(ByteArray(obj["hash"])),
            confirmations=obj["confirmations"],
            size=obj["size"],
            height=obj["height"],
            version=obj["version"],
            merkleRoot=ByteArray(obj["merkleroot"]),
            stakeRoot=ByteArray(obj["stakeroot"]),
            time=obj["time"],
            nonce=obj["nonce"],
            voteBits=obj["votebits"],
            finalState=ByteArray(obj["finalstate"]),
            voters=obj["voters"],
            freshStake=obj["freshstake"],
            revocations=obj["revocations"],
            poolSize=obj["poolsize"],
            bits=ByteArray(obj["bits"]),
            sBits=obj["sbits"],
            extraData=ByteArray(obj["extradata"]),
            stakeVersion=obj["stakeversion"],
            difficulty=obj["difficulty"],
            chainWork=ByteArray(obj["chainwork"]),
            previousHash=reversed(ByteArray(obj["previousblockhash"])),
            nextHash=reversed(ByteArray(obj["nextblockhash"]))
            if "nextblockhash" in obj
            else None,
            txHash=[reversed(ByteArray(rawTx)) for rawTx in obj["tx"]]
            if "tx" in obj
            else [],
            rawTx=[RawTransactionResult.parse(tx) for tx in obj["rawtx"]]
            if "rawtx" in obj
            else [],
            sTxHash=[reversed(ByteArray(rawTx)) for rawTx in obj["stx"]]
            if "stx" in obj
            else [],
            rawSTx=[RawTransactionResult.parse(stx) for stx in obj["rawstx"]]
            if "rawstx" in obj
            else [],
        )


class GetAddedNodeInfoResultAddr:
    """
    Models the addresses data of a GetAddedNodeInfoResult.
    """

    def __init__(
        self, address, connected,
    ):
        """
        Args:
            address (str): The ip address for this DNS entry.
            connected (str): The connection 'direction' (inbound/outbound/false).
        """
        self.address = address
        self.connected = connected

    @staticmethod
    def parse(obj):
        """
        Parse the GetAddedNodeInfoResultAddr from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetAddedNodeInfoResultAddr: The GetAddedNodeInfoResultAddr.
        """
        return GetAddedNodeInfoResultAddr(
            address=obj["address"], connected=obj["connected"],
        )

    def __eq__(self, other):
        try:
            return (self.address == other.address) and (
                self.connected == other.connected
            )
        except AttributeError:
            return False


class GetAddedNodeInfoResult:
    """
    Models data returned by the getAddedNodeInfo command.
    """

    def __init__(
        self, addedNode, connected=None, addresses=None,
    ):
        """
        Args:
            addedNode (str): The ip address or domain of the added peer.
            connected (bool): Whether or not the peer is currently connected or
                None.
            addresses (list(GetAddedNodeInfoResultAddr)) DNS lookup and
                connection information about the peer. May be Empty.
        """
        self.addedNode = addedNode
        self.connected = connected
        self.addresses = addresses if addresses else []

    @staticmethod
    def parse(obj):
        """
        Parse the GetAddedNodeInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetAddedNodeInfoResult: The GetAddedNodeInfoResult.
        """
        return GetAddedNodeInfoResult(
            addedNode=obj["addednode"],
            connected=obj.get("connected"),
            addresses=[
                GetAddedNodeInfoResultAddr.parse(addr) for addr in obj.get("addresses")
            ],
        )


class GetChainTipsResult:
    """
    Models data returned by the getChainTips command.
    """

    def __init__(
        self, height, blockHash, branchLen, status,
    ):
        """
        Args:
            height (int): The height of the chain tip.
            blockHash (ByteArray): The block hash of the chain tip.
            branchLen (int): The length of the branch that connects the tip to
                the main chain (0 for the main chain tip).
            status (str): The status of the chain (active, invalid, headers-only,
                valid-fork, valid-headers).
        """
        self.height = height
        self.blockHash = blockHash
        self.branchLen = branchLen
        self.status = status

    @staticmethod
    def parse(obj):
        """
        Parse the GetChainTipsResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetChainTipsResult: The GetChainTipsResult.
        """
        return GetChainTipsResult(
            height=obj["height"],
            blockHash=reversed(ByteArray(obj["hash"])),
            branchLen=obj["branchlen"],
            status=obj["status"],
        )


class GetBlockSubsidyResult:
    """
    Models data returned by the getBockSubsidy command.
    """

    def __init__(
        self, developer, pos, sPoW, total,
    ):
        """
        Args:
            developer (int): The developer subsidy.
            pos (int): The Proof-of-Stake subsidy.
            sPoW (int): The Proof-of-Work subsidy.
            total (int): The total subsidy.
        """
        self.developer = developer
        self.pos = pos
        self.sPoW = sPoW
        self.total = total

    @staticmethod
    def parse(obj):
        """
        Parse the GetBlockSubsidyResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetBlockSubsidyResult: The GetBlockSubsidyResult.
        """
        return GetBlockSubsidyResult(
            developer=obj["developer"],
            pos=obj["pos"],
            sPoW=obj["pow"],
            total=obj["total"],
        )


class GetCFilterV2Result:
    """
    Models data returned by the getCFilterV2 command.
    """

    def __init__(
        self, blockHash, data, proofIndex, proofHashes,
    ):
        """
        Args:
            blockHash (ByteArray): The block hash for which the filter includes data.
            data (ByteArray): Bytes of the serialized filter.
            proofIndex (int): The index of the leaf that represents the filter
                hash in the header commitment.
            proofHashes (list(str)): The hashes needed to prove the filter is
                committed to by the header commitment.
        """
        self.blockHash = blockHash
        self.data = data
        self.proofIndex = proofIndex
        self.proofHashes = proofHashes

    @staticmethod
    def parse(obj):
        """
        Parse the GetCFilterV2Result from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetCFilterV2Result: The GetCFilterV2Result.
        """
        return GetCFilterV2Result(
            blockHash=reversed(ByteArray(obj["blockhash"])),
            data=ByteArray(obj["data"]),
            proofIndex=obj["proofindex"],
            proofHashes=obj["proofhashes"],
        )


class GetBlockHeaderVerboseResult:
    """
    Models data returned by the verbose getBlockHeader command.
    """

    def __init__(
        self,
        blockHash,
        confirmations,
        version,
        merkleRoot,
        stakeRoot,
        voteBits,
        finalState,
        voters,
        freshStake,
        revocations,
        poolSize,
        bits,
        sBits,
        height,
        size,
        time,
        nonce,
        extraData,
        stakeVersion,
        difficulty,
        chainWork,
        previousHash=None,
        nextHash=None,
    ):
        """
        Args:
            blockHash (ByteArray): The hash of the block.
            confirmations (int): The number of confirmations.
            version (int): The block version.
            merkleRoot (ByteArray): The merkle root of the regular transaction tree.
            stakeRoot (ByteArray): The merkle root of the stake transaction tree.
            voteBits (int): The vote bits.
            finalState (ByteArray): The final state value of the ticket pool.
            voters (int): The number of votes in the block.
            freshStake (int): The number of new tickets in the block.
            revocations (int): The number of revocations in the block.
            poolSize (int): The size of the live ticket pool.
            bits (ByteArray): The bits which represent the block difficulty.
            sBits (float): The stake difficulty in coins.
            height (int): The height of the block in the block chain.
            size (int): The size of the block in bytes.
            time (int): The block time in seconds since 1 Jan 1970 GMT.
            nonce (int): The block nonce.
            extraData (ByteArray): Extra data field for the requested block.
            stakeVersion (int): The stake version of the block.
            difficulty (float): The proof-of-work difficulty as a multiple of
                the minimum difficulty.
            chainWork (ByteArray): The total number of hashes expected to produce
                the chain up to the block.
            previousHash (ByteArray): The hash of the previous block or None.
            nextHash (ByteArray): The hash of the next block or None.
        """
        self.blockHash = blockHash
        self.confirmations = confirmations
        self.version = version
        self.merkleRoot = merkleRoot
        self.stakeRoot = stakeRoot
        self.voteBits = voteBits
        self.finalState = finalState
        self.voters = voters
        self.freshStake = freshStake
        self.revocations = revocations
        self.poolSize = poolSize
        self.bits = bits
        self.sBits = sBits
        self.height = height
        self.size = size
        self.time = time
        self.nonce = nonce
        self.extraData = extraData
        self.stakeVersion = stakeVersion
        self.difficulty = difficulty
        self.chainWork = chainWork
        self.previousHash = previousHash
        self.nextHash = nextHash

    @staticmethod
    def parse(obj):
        """
        Parse the GetBlockHeaderVerboseResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetBlockHeaderVerboseResult: The GetBlockHeaderVerboseResult.
        """
        return GetBlockHeaderVerboseResult(
            blockHash=reversed(ByteArray(obj["hash"])),
            confirmations=obj["confirmations"],
            version=obj["version"],
            merkleRoot=ByteArray(obj["merkleroot"]),
            stakeRoot=ByteArray(obj["stakeroot"]),
            voteBits=obj["votebits"],
            finalState=ByteArray(obj["finalstate"]),
            voters=obj["voters"],
            freshStake=obj["freshstake"],
            revocations=obj["revocations"],
            poolSize=obj["poolsize"],
            bits=ByteArray(obj["bits"]),
            sBits=obj["sbits"],
            height=obj["height"],
            size=obj["size"],
            time=obj["time"],
            nonce=obj["nonce"],
            extraData=ByteArray(obj["extradata"]),
            stakeVersion=obj["stakeversion"],
            difficulty=obj["difficulty"],
            chainWork=ByteArray(obj["chainwork"]),
            previousHash=reversed(ByteArray(obj["previoushash"]))
            if "previoushash" in obj
            else None,
            nextHash=reversed(ByteArray(obj["nexthash"]))
            if "nexthash" in obj
            else None,
        )


class GetRawMempoolVerboseResult:
    """
    Models data returned by the verbose getRawMempool command.
    """

    def __init__(
        self, size, fee, time, height, startingPriority, currentPriority, depends,
    ):
        """
        Args:
            size (int): Transaction size in bytes.
            fee (float): Transaction fee in decred.
            time (int): Local time transaction entered pool in seconds since
                1 Jan 1970 GMT.
            height (int): Block height when transaction entered the pool.
            startingPriority (float): Priority when transaction entered the pool.
            currentPriority (float): Current priority.
            depends (list(ByteArray)): Unconfirmed transactions used as inputs for
                this transaction.
        """
        self.size = size
        self.fee = fee
        self.time = time
        self.height = height
        self.startingPriority = startingPriority
        self.currentPriority = currentPriority
        self.depends = depends

    @staticmethod
    def parse(obj):
        """
        Parse the GetRawMempoolVerboseResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetRawMempoolVerboseResult: The GetRawMempoolVerboseResult.
        """
        return GetRawMempoolVerboseResult(
            size=obj["size"],
            fee=obj["fee"],
            time=obj["time"],
            height=obj["height"],
            startingPriority=obj["startingpriority"],
            currentPriority=obj["currentpriority"],
            depends=[reversed(ByteArray(txid)) for txid in obj["depends"]],
        )


class GetPeerInfoResult:
    """
    Models data returned by the getPeerInfo command.
    """

    def __init__(
        self,
        nodeID,
        addr,
        services,
        relayTxes,
        lastSend,
        lastRecv,
        bytesSent,
        bytesRecv,
        connTime,
        timeOffset,
        pingTime,
        version,
        subVer,
        inbound,
        startingHeight,
        banScore,
        syncNode,
        addrLocal=None,
        pingWait=None,
        currentHeight=None,
    ):
        """
        Args:
            nodeID (int): A unique node ID.
            addr (str): The ip address and port of the peer.
            services (ByteArray): Services bitmask which represents the services
                supported by the peer.
            relayTxes (bool): Peer has requested transactions be relayed to it.
            lastSend (int): Time the last message was received in seconds since
                1 Jan 1970 GMT.
            lastRecv (int): Time the last message was sent in seconds since 1
                Jan 1970 GMT.
            bytesSent (int): Total bytes sent.
            bytesRecv (int): Total bytes received.
            connTime (int): Time the connection was made in seconds since 1 Jan
                1970 GMT.
            timeOffset (int): The time offset of the peer.
            pingTime (float): Number of microseconds the last ping took.
            version (int): The protocol version of the peer.
            subVer (str): The user agent of the peer.
            inbound (bool): Whether or not the peer is an inbound connection.
            startingHeight (int): The latest block height the peer knew about
                when the connection was established.
            banScore (int): The ban score.
            syncNode (bool): Whether or not the peer is the sync peer.
            addrLocal (str): Local address or None.
            pingWait (float): Number of microseconds a queued ping has been
                waiting for a response or None.
            currentHeight (int): The current height of the peer or None.
        """
        self.nodeID = nodeID
        self.addr = addr
        self.services = services
        self.relayTxes = relayTxes
        self.lastSend = lastSend
        self.lastRecv = lastRecv
        self.bytesSent = bytesSent
        self.bytesRecv = bytesRecv
        self.connTime = connTime
        self.timeOffset = timeOffset
        self.pingTime = pingTime
        self.version = version
        self.subVer = subVer
        self.inbound = inbound
        self.startingHeight = startingHeight
        self.banScore = banScore
        self.syncNode = syncNode
        self.addrLocal = addrLocal
        self.pingWait = pingWait
        self.currentHeight = currentHeight

    @staticmethod
    def parse(obj):
        """
        Parse the GetPeerInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetPeerInfoResult: The GetPeerInfoResult.
        """
        return GetPeerInfoResult(
            nodeID=obj["id"],
            addr=obj["addr"],
            services=ByteArray(obj["services"]),
            relayTxes=obj["relaytxes"],
            lastSend=obj["lastsend"],
            lastRecv=obj["lastrecv"],
            bytesSent=obj["bytessent"],
            bytesRecv=obj["bytesrecv"],
            connTime=obj["conntime"],
            timeOffset=obj["timeoffset"],
            pingTime=obj["pingtime"],
            version=obj["version"],
            subVer=obj["subver"],
            inbound=obj["inbound"],
            startingHeight=obj["startingheight"],
            banScore=obj["banscore"],
            syncNode=obj["syncnode"],
            addrLocal=obj.get("addrlocal"),
            pingWait=obj.get("pingwait"),
            currentHeight=obj.get("currentheight"),
        )


class LocalAddressesResult:
    """
    Models the localAddresses data for a GetNetworkInfoResult.
    """

    def __init__(
        self, address, port, score,
    ):
        """
        address (str): The local address being listened on.
        port (int): The port being listened on for the associated local address.
        score (int): Reserved.
        """
        self.address = address
        self.port = port
        self.score = score

    @staticmethod
    def parse(obj):
        """
        Parse the LocalAddressesResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            LocalAddressesResult: The LocalAddressesResult.
        """
        return LocalAddressesResult(
            address=obj["address"], port=obj["port"], score=obj["score"],
        )


class NetworksResult:
    """
    Models the networks data for a GetNetworkInfoResult.
    """

    def __init__(
        self, name, limited, reachable, proxy, proxyRandomizeCredentials,
    ):
        """
        Args:
            name (str): The name of the network interface.
            limited (bool): True if only connections to the network are allowed.
            reachable (bool): True if connections can be made to or from the
                network.
            proxy (str): The proxy set for the network.
            proxyRandomizeCredentials (bool): True if randomized credentials are
                set for the proxy.
        """
        self.name = name
        self.limited = limited
        self.reachable = reachable
        self.proxy = proxy
        self.proxyRandomizeCredentials = proxyRandomizeCredentials

    @staticmethod
    def parse(obj):
        """
        Parse the NetworkResults from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            NetworkResults: The NetworkResults.
        """
        return NetworksResult(
            name=obj["name"],
            limited=obj["limited"],
            reachable=obj["reachable"],
            proxy=obj["proxy"],
            proxyRandomizeCredentials=obj["proxyrandomizecredentials"],
        )


class GetNetworkInfoResult:
    """
    Models data returned by the getNetworkInfo command.
    """

    def __init__(
        self,
        version,
        subVersion,
        protocolVersion,
        timeOffset,
        connections,
        networks,
        relayFee,
        localAddresses,
        localServices,
    ):
        """
        Args:
            version (int): The version of the node as a numeric.
            subVersion (str): The subversion of the node, as advertised to peers.
            protocolVersion (int): The protocol version of the node.
            timeOffset (int): The node clock offset in seconds.
            connections (int): The total number of open connections for the node.
            networks (list(NetworksResult)): An array of objects describing
                IPV4, IPV6 and Onion network interface states.
            relayFee (float): The minimum required transaction fee for the node.
            localAddresses (list(LocalAddressesResult)): An array of objects
                describing local addresses being listened on by the node.
            localServices (str): The services supported by the node, as
                advertised in its version message.
        """
        self.version = version
        self.subVersion = subVersion
        self.protocolVersion = protocolVersion
        self.timeOffset = timeOffset
        self.connections = connections
        self.networks = networks
        self.relayFee = relayFee
        self.localAddresses = localAddresses
        self.localServices = localServices

    @staticmethod
    def parse(obj):
        """
        Parse the GetNetworkInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetNetworkInfoResult: The GetNetworkInfoResult.
        """
        return GetNetworkInfoResult(
            version=obj["version"],
            subVersion=obj["subversion"],
            protocolVersion=obj["protocolversion"],
            timeOffset=obj["timeoffset"],
            connections=obj["connections"],
            networks=[NetworksResult.parse(net) for net in obj["networks"]],
            relayFee=obj["relayfee"],
            localAddresses=[
                LocalAddressesResult.parse(addr) for addr in obj["localaddresses"]
            ],
            localServices=obj["localservices"],
        )


class GetNetTotalsResult:
    """
    Models data returned by the getNetTotals command.
    """

    def __init__(
        self, totalBytesRecv, totalBytesSent, timeMillis,
    ):
        """
        totalBytesRecv (int): Total bytes received.
        totalBytesSent (int): Total bytes sent.
        timeMillis (int): Number of milliseconds since 1 Jan 1970 GMT.
        """
        self.totalBytesRecv = totalBytesRecv
        self.totalBytesSent = totalBytesSent
        self.timeMillis = timeMillis

    @staticmethod
    def parse(obj):
        """
        Parse the GetNetTotalResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetNetTotalsResult: The GetNetTotalsResult.
        """
        return GetNetTotalsResult(
            totalBytesRecv=obj["totalbytesrecv"],
            totalBytesSent=obj["totalbytessent"],
            timeMillis=obj["timemillis"],
        )


class GetMiningInfoResult:
    """
    Models data returned by the getMiningInfo command.
    """

    def __init__(
        self,
        blocks,
        currentBlockSize,
        currentBlockTx,
        difficulty,
        stakeDifficulty,
        errors,
        generate,
        numCPUs,
        hashesPerSec,
        networkHashPS,
        pooledTx,
        testNet,
    ):
        """
        Args:
            blocks (int): Height of the latest best block.
            currentBlockSize (int): Size of the latest best block.
            currentBlockTx (int): Number of transactions in the latest best block.
            difficulty (int): Current target difficulty.
            stakeDifficulty (int): Stake difficulty required for the next block.
            errors (str):  Any current errors.
            generate (bool): Whether or not server is set to generate coins.
            numCPUs (int): Number of processors to use for coin generation
                (-1 when disabled).
            hashesPerSec (int): Recent hashes per second performance measurement
                while generating coins.
            networkHashPS (int): Estimated network hashes per second for the
                most recent blocks.
            pooledTx (int): Number of transactions in the memory pool.
            testNet (bool): Whether or not server is using testnet.
        """
        self.blocks = blocks
        self.currentBlockSize = currentBlockSize
        self.currentBlockTx = currentBlockTx
        self.difficulty = difficulty
        self.stakeDifficulty = stakeDifficulty
        self.errors = errors
        self.generate = generate
        self.numCPUs = numCPUs
        self.hashesPerSec = hashesPerSec
        self.networkHashPS = networkHashPS
        self.pooledTx = pooledTx
        self.testNet = testNet

    @staticmethod
    def parse(obj):
        """
        Parse the GetMiningInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetMiningInfoResult: The GetMiningInfoResult.
        """
        return GetMiningInfoResult(
            blocks=obj["blocks"],
            currentBlockSize=obj["currentblocksize"],
            currentBlockTx=obj["currentblocktx"],
            difficulty=obj["difficulty"],
            stakeDifficulty=obj["stakedifficulty"],
            errors=obj["errors"],
            generate=obj["generate"],
            numCPUs=obj["genproclimit"],
            hashesPerSec=obj["hashespersec"],
            networkHashPS=obj["networkhashps"],
            pooledTx=obj["pooledtx"],
            testNet=obj["testnet"],
        )


class GetMempoolInfoResult:
    """
    Models data returned by the getMempoolInfo command.
    """

    def __init__(
        self, size, Bytes,
    ):
        """
        Args:
            size (int): Number of transactions in the mempool.
            bytes (int): Size in bytes of the mempool.
        """
        self.size = size
        self.bytes = Bytes

    @staticmethod
    def parse(obj):
        """
        Parse the GetMempoolInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetMempoolInfoResult: The GetMempoolInfoResult.
        """
        return GetMempoolInfoResult(size=obj["size"], Bytes=obj["bytes"])


class InfoChainResult:
    """
    Models data returned by the getInfo command.
    """

    def __init__(
        self,
        version,
        protocolVersion,
        blocks,
        timeOffset,
        connections,
        proxy,
        difficulty,
        testNet,
        relayFee,
        errors,
    ):
        """
        Args:
            version (int): The version of the server.
            protocolVersion (int): The latest supported protocol version.
            blocks (int): The number of blocks processed.
            timeOffset (int): The time offset.
            connections (int): The number of connected peers.
            proxy (str): The proxy used by the server.
            difficulty (int): The current target difficulty.
            testnet (bool): Whether or not server is using testnet.
            relayFee (int): The minimum relay fee for non-free transactions in DCR/KB.
            errors (str): Any current errors.
        """
        self.version = version
        self.protocolVersion = protocolVersion
        self.blocks = blocks
        self.timeOffset = timeOffset
        self.connections = connections
        self.proxy = proxy
        self.difficulty = difficulty
        self.testNet = testNet
        self.relayFee = relayFee
        self.errors = errors

    @staticmethod
    def parse(obj):
        """
        Parse the InfoChainResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            InfoChainResult: The InfoChainResult.
        """
        return InfoChainResult(
            version=obj["version"],
            protocolVersion=obj["protocolversion"],
            blocks=obj["blocks"],
            timeOffset=obj["timeoffset"],
            connections=obj["connections"],
            proxy=obj["proxy"],
            difficulty=obj["difficulty"],
            testNet=obj["testnet"],
            relayFee=obj["relayfee"],
            errors=obj["errors"],
        )


class GetWorkResult:
    """
    Models data returned by the getWork command.
    """

    def __init__(
        self, data, target,
    ):
        """
        Args:
            data (ByteArray): Block data.
            target (ByteArray): Little-endian hash target.
        """
        self.data = data
        self.target = target

    @staticmethod
    def parse(obj):
        """
        Parse the GetWorkResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetWorkResult: The GetWorkResult.
        """
        return GetWorkResult(
            data=ByteArray(obj["data"]), target=ByteArray(obj["target"])
        )


class GetTxOutResult:
    """
    Models data returned by the getTxOut command.
    """

    def __init__(
        self, bestBlock, confirmations, value, scriptPubKey, version, coinbase,
    ):
        """
        Args:
            bestBlock (ByteArray): The block hash that contains the transaction
                output
            confirmations (int): The number of confirmations
            value (float): The transaction amount in DCR
            scriptPubKey (ScriptPubKeyResult): The public key script used to pay
                coins.
            version (int): The transaction version
            coinbase (bool): Whether or not the transaction is a coinbase
        """
        self.bestBlock = bestBlock
        self.confirmations = confirmations
        self.value = value
        self.scriptPubKey = scriptPubKey
        self.version = version
        self.coinbase = coinbase

    @staticmethod
    def parse(obj):
        """
        Parse the GetTxOutResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetTxOutResult: The GetTxOutResult.
        """
        return GetTxOutResult(
            bestBlock=reversed(ByteArray(obj["bestblock"])),
            confirmations=obj["confirmations"],
            value=obj["value"],
            scriptPubKey=ScriptPubKeyResult.parse(obj["scriptPubKey"]),
            version=obj["version"],
            coinbase=obj["coinbase"],
        )


class GetVoteInfoResult:
    """
    Models data returned by the getVoteInfo command.
    """

    def __init__(
        self,
        currentHeight,
        startHeight,
        endHeight,
        blockHash,
        voteVersion,
        quorum,
        totalVotes,
        agendas=None,
    ):
        """
        currentHeight (int): Top of the chain height.
        startHeight (int): The start height of this voting window.
        endHeight (int): The end height of this voting window.
        blockHash (ByteArray): The hash of the current height block.
        voteVersion (int): Selected vote version.
        quorum (int): Minimum amount of votes required.
        totalVotes (int): Total votes.
        agendas list(Agenda): All agendas for this stake version. May be empty.
        """
        self.currentHeight = currentHeight
        self.startHeight = startHeight
        self.endHeight = endHeight
        self.blockHash = blockHash
        self.voteVersion = voteVersion
        self.quorum = quorum
        self.totalVotes = totalVotes
        self.agendas = agendas if agendas else []

    @staticmethod
    def parse(obj):
        """
        Parse the GetVoteInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetVoteInfoResult: The GetVoteInfoResult.
        """
        return GetVoteInfoResult(
            currentHeight=obj["currentheight"],
            startHeight=obj["startheight"],
            endHeight=obj["endheight"],
            blockHash=reversed(ByteArray(obj["hash"])),
            voteVersion=obj["voteversion"],
            quorum=obj["quorum"],
            totalVotes=obj["totalvotes"],
            agendas=[agenda.Agenda.parse(ag) for ag in obj["agendas"]]
            if "agendas" in obj
            else [],
        )


class VersionBits:
    """
    Models a generic version:bits tuple for a GetStakeVersionsResult.
    """

    def __init__(
        self, version, bits,
    ):
        """
        Args:
            version (int): The version of the vote.
            bits (int): The bits assigned by the vote.
        """
        self.version = version
        self.bits = bits

    @staticmethod
    def parse(obj):
        """
        Parse the VersionBits from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            VersionBits: The parsed VersionBits.
        """
        return VersionBits(version=obj["version"], bits=obj["bits"])


class GetStakeVersionsResult:
    """
    Models data returned by the getStakeVersions command.
    """

    def __init__(
        self, blockHash, height, blockVersion, stakeVersion, votes,
    ):
        """
        Args:
            blockHash (ByteArray): Hash of the block.
            height (int): Height of the block.
            blockVersion (int): The block version.
            stakeVersion (int): The stake version of the block.
            votes list(VersionBits): The version and bits of each vote in the
                block.
        """
        self.blockHash = blockHash
        self.height = height
        self.blockVersion = blockVersion
        self.stakeVersion = stakeVersion
        self.votes = votes

    @staticmethod
    def parse(obj):
        """
        Parse the StakeVersionsResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            StakeVersionsResult: The StakeVersionsResult.
        """
        return GetStakeVersionsResult(
            blockHash=reversed(ByteArray(obj["hash"])),
            height=obj["height"],
            blockVersion=obj["blockversion"],
            stakeVersion=obj["stakeversion"],
            votes=[VersionBits.parse(vote) for vote in obj["votes"]],
        )


class VersionCount:
    """
    Models a generic version:count tuple for a VersionInterval for a
    GetStakeVersionInfoResult.
    """

    def __init__(
        self, version, count,
    ):
        """
        version (int): Version of the vote.
        count (int): Number of votes.
        """
        self.version = version
        self.count = count

    @staticmethod
    def parse(obj):
        """
        Parse the VersionCount from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            VersionCount: The parsed VersionCount.
        """
        return VersionCount(version=obj["version"], count=obj["count"])


class VersionInterval:
    """
    Models intervals data for a GetStakeVersionInfoResult.
    """

    def __init__(
        self, startHeight, endHeight, poSVersions, voteVersions,
    ):
        """
        Args:
            startHeight (int): Start of the interval.
            endHeight (int): End of the interval.
            posVersions list(VersionCount): Tally of the stake versions.
            voteVersions list(VersionCount): Tally of all vote versions.
        """
        self.startHeight = startHeight
        self.endHeight = endHeight
        self.poSVersions = poSVersions
        self.voteVersions = voteVersions

    @staticmethod
    def parse(obj):
        """
        Parse the VersionInterval from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            VersionInterval: The parsed VersionInterval.
        """
        return VersionInterval(
            startHeight=obj["startheight"],
            endHeight=obj["endheight"],
            poSVersions=[VersionCount.parse(ver) for ver in obj["posversions"]],
            voteVersions=[VersionCount.parse(ver) for ver in obj["voteversions"]],
        )


class GetStakeVersionInfoResult:
    """
    Models data returned by the getStakeVersionInfo command.
    """

    def __init__(
        self, currentHeight, blockHash, intervals,
    ):
        """
        Args:
            currentHeight (int): Top of the chain height.
            blockHash (ByteArray): Top of the chain hash.
            intervals list(VersionInterval): Array of total stake and vote counts.
        """
        self.currentHeight = currentHeight
        self.blockHash = blockHash
        self.intervals = intervals

    @staticmethod
    def parse(obj):
        """
        Parse the GetStakeVersionInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetStakeVersionInfoResult: The GetStakeVersionInfoResult.
        """
        return GetStakeVersionInfoResult(
            currentHeight=obj["currentheight"],
            blockHash=reversed(ByteArray(obj["hash"])),
            intervals=[VersionInterval.parse(ver) for ver in obj["intervals"]],
        )


class GetStakeDifficultyResult:
    """
    Models data returned by the getStakeDifficulty command.
    """

    def __init__(
        self, currentStakeDifficulty, nextStakeDifficulty,
    ):
        """
        currentStakeDifficulty (float): The current top block's stake difficulty
        nextStakeDifficulty (float): The calculated stake difficulty of the next
            block
        """
        self.currentStakeDifficulty = currentStakeDifficulty
        self.nextStakeDifficulty = nextStakeDifficulty

    @staticmethod
    def parse(obj):
        """
        Parse the GetStakeDifficultyResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetStakeDifficultyResult: The GetStakeDifficultyResult.
        """
        return GetStakeDifficultyResult(
            currentStakeDifficulty=obj["current"], nextStakeDifficulty=obj["next"],
        )


class FeeInfoResult:
    """
    Models data returned by the ticketFeeInfo and txFeeInfo commands.
    """

    def __init__(
        self,
        number,
        Min,
        Max,
        mean,
        median,
        stdDev,
        height=None,
        startHeight=None,
        endHeight=None,
    ):
        """
        Args:
            number (int): Number of transactions.
            min (float): Minimum transaction fee.
            max (float): Maximum transaction fee in the block.
            mean (float): Mean of transaction fees in the block.
            median (float): Median of transaction fees in the block.
            stddev (float): Standard deviation of transaction fees in the block.
            height (int): Height (only for blocks) or None.
            startHeight (int): Start height (only for windows) or None.
            endHeight (int): End height (only for windows) or None.
        """
        self.number = number
        self.min = Min
        self.max = Max
        self.mean = mean
        self.median = median
        self.stdDev = stdDev
        self.height = height
        self.startHeight = startHeight
        self.endHeight = endHeight

    @staticmethod
    def parse(obj):
        """
        Parse the FeeInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            FeeInfoResult: The FeeInfoResult.
        """
        return FeeInfoResult(
            number=obj["number"],
            Min=obj["min"],
            Max=obj["max"],
            mean=obj["mean"],
            median=obj["median"],
            stdDev=obj["stddev"],
            height=obj.get("height"),
            startHeight=obj.get("startheight"),
            endHeight=obj.get("endheight"),
        )


class TicketFeeInfoResult:
    """
    Models data returned by the ticketFeeInfo command.
    """

    def __init__(
        self, feeInfoMempool, feeInfoBlocks=None, feeInfoWindows=None,
    ):
        """
        Args:
            feeInfoMempool (FeeInfoResult): Ticket fee information for all
                tickets in the mempool (units: DCR/kB)
            feeInfoBlocks (list(FeeInfoResult)): Ticket fee information for a
                given list of blocks descending from the chain tip (units: DCR/kB)
            feeInfoWindows (list(FeeInfoResult)): Ticket fee information for a
                window period where the stake difficulty was the same (units: DCR/kB)
        """
        self.feeInfoMempool = feeInfoMempool
        self.feeInfoBlocks = feeInfoBlocks if feeInfoBlocks else []
        self.feeInfoWindows = feeInfoWindows if feeInfoWindows else []

    @staticmethod
    def parse(obj):
        """
        Parse the TicketFeeInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            TicketFeeInfoResult: The TicketFeeInfoResult.
        """
        return TicketFeeInfoResult(
            feeInfoMempool=obj["feeinfomempool"],
            feeInfoBlocks=[FeeInfoResult.parse(info) for info in obj["feeinfoblocks"]]
            if "feeinfoblocks" in obj and obj["feeinfoblocks"]
            else [],
            feeInfoWindows=[FeeInfoResult.parse(info) for info in obj["feeinfowindows"]]
            if "feeinfowindows" in obj and obj["feeinfowindows"]
            else [],
        )


class TxFeeInfoResult:
    """
    Models data returned by the txFeeInfo command.
    """

    def __init__(
        self, feeInfoMempool, feeInfoBlocks=None, feeInfoRange=None,
    ):
        """
        Args:
            feeinfomempool (FeeInfoResult): Transaction fee information for all
                regular transactions in the mempool (units: DCR/kB)
            feeinfoblocks (list(FeeInfoResult)): Transaction fee information
                for a given list of blocks descending from the chain tip (units: DCR/kB)
            feeinforange (FeeInfoResult): Transaction fee information for a
                window period where the stake difficulty was the same (units: DCR/kB)
        """
        self.feeInfoMempool = feeInfoMempool
        self.feeInfoBlocks = feeInfoBlocks if feeInfoBlocks else []
        self.feeInfoRange = feeInfoRange

    @staticmethod
    def parse(obj):
        """
        Parse the TxFeeInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            TxFeeInfoResult: The TxFeeInfoResult.
        """
        return TxFeeInfoResult(
            feeInfoMempool=obj["feeinfomempool"],
            feeInfoBlocks=[FeeInfoResult.parse(info) for info in obj["feeinfoblocks"]]
            if "feeinfoblocks" in obj and obj["feeinfoblocks"]
            else [],
            feeInfoRange=FeeInfoResult.parse(obj["feeinforange"])
            if "feeinforange" in obj
            else None,
        )


class GetBestBlockResult:
    """
    Models data returned by the getBestBlock command.
    """

    def __init__(self, blockHash, height):
        """
        Args:
            blockHash (ByteArray): The best block's hash.
            height (int): The best block's height.
        """
        self.hash = blockHash
        self.height = height

    @staticmethod
    def parse(obj):
        """
        Parse the GetBestBlockResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetBestBlockResult: The GetBestBlockResult.
        """
        blockHash = reversed(ByteArray(obj["hash"]))
        return GetBestBlockResult(blockHash=blockHash, height=obj["height"])


class GetBlockChainInfoResult:
    """
    Models data returned by the getBlockChainInfo command.
    """

    def __init__(
        self,
        chain,
        blocks,
        headers,
        syncHeight,
        bestBlockHash,
        difficultyRatio,
        verificationProgress,
        chainWork,
        initialBlockDownload,
        maxBlockSize,
        deployments,
    ):
        """
        Args:
            chain (str):  The current network name.
            blocks (int): The number of blocks in the current best chain.
            headers (int): The number of validated block headers that
                comprise the target best chain.
            syncHeight (int): The latest known block height being synced to.
            bestBlockHash (ByteArray): The block hash of the current best chain
                tip.
            difficultyRatio (float): The current proof-of-work difficulty as
                a multiple of the minimum difficulty.
            verificationProgress (float): The chain verification progress
                estimate.
            chainWork (ByteArray): Total work done for the chain.
            initialBlockDownload (bool): Best guess of whether this node is
                in the initial block download mode used to catch up the chain
                when it is far behind
            maxBlockSize (int): The maximum allowed block size.
            deployments (dict(str->AgendaInfo)):  Network consensus deployments.
        """
        self.chain = chain
        self.blocks = blocks
        self.headers = headers
        self.syncHeight = syncHeight
        self.bestBlockHash = bestBlockHash
        self.difficultyRatio = difficultyRatio
        self.verificationProgress = verificationProgress
        self.chainWork = chainWork
        self.initialBlockDownload = initialBlockDownload
        self.maxBlockSize = maxBlockSize
        self.deployments = deployments

    @staticmethod
    def parse(obj):
        """
        Parse the GetBlockChainInfoResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            GetBlockChainInfoResult: The GetBlockChainInfoResult.
        """
        return GetBlockChainInfoResult(
            chain=obj["chain"],
            blocks=obj["blocks"],
            headers=obj["headers"],
            syncHeight=obj["syncheight"],
            bestBlockHash=reversed(ByteArray(obj["bestblockhash"])),
            difficultyRatio=obj["difficultyratio"],
            verificationProgress=obj["verificationprogress"],
            chainWork=ByteArray(obj["chainwork"]),
            initialBlockDownload=obj["initialblockdownload"],
            maxBlockSize=obj["maxblocksize"],
            deployments={
                k: agenda.AgendaInfo.parse(v) for k, v in obj["deployments"].items()
            },
        )


class RawTransactionResult:
    """
    Models data returned by the searchRawTransactions, decodeRawTransaction,
    getblock, and getRawTransaction commands.
    """

    def __init__(
        self,
        txHash,
        version,
        lockTime,
        expiry,
        vin,
        vout,
        tx=None,
        blockHash=None,
        blockHeight=None,
        blockIndex=None,
        confirmations=None,
        time=None,
        blockTime=None,
    ):
        """
        Args:
            txHash (ByteArray):  The hash of the transaction.
            version (int): The transaction version.
            locktime (int): The transaction lock time.
            expiry (int): The transaction expiry.
            vin (list(object)): The transaction inputs.
            vout (list(object)): The transaction outputs.
            tx (msgtx.MsgTx): msgtx.MsgTx transaction or None.
            blockHash (ByteArray): The hash of the block the contains the
                transaction or None.
            blockHeight (int): The height of the block that contains the
                transaction or None.
            blockIndex (int): The index within the array of transactions
                contained by the block or None.
            confirmations (int): Number of confirmations of the block or None.
            time (int): Transaction time in seconds since 1 Jan 1970 GMT or None.
            blockTime (int): Block time in seconds since the 1 Jan 1970 GMT or None.
        """
        self.txHash = txHash
        self.version = version
        self.lockTime = lockTime
        self.expiry = expiry
        self.vin = vin
        self.vout = vout
        self.tx = tx
        self.blockHash = blockHash
        self.blockHeight = blockHeight
        self.blockIndex = blockIndex
        self.confirmations = confirmations
        self.time = time
        self.blockTime = blockTime

    @staticmethod
    def parse(obj):
        """
        Parse the RawTransactionResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            RawTransactionResult: The RawTransactionResult.
        """
        return RawTransactionResult(
            txHash=reversed(ByteArray(obj["txid"])),
            version=obj["version"],
            lockTime=obj["locktime"],
            expiry=obj["expiry"],
            vin=[Vin.parse(vin) for vin in obj["vin"]],
            vout=[Vout.parse(vout) for vout in obj["vout"]],
            tx=MsgTx.deserialize((obj["hex"])) if "hex" in obj else None,
            blockHash=reversed(ByteArray(obj["blockhash"]))
            if "blockhash" in obj
            else None,
            blockHeight=obj.get("blockheight"),
            blockIndex=obj.get("blockindex"),
            confirmations=obj.get("confirmations"),
            time=obj.get("time"),
            blockTime=obj.get("blocktime"),
        )


class PrevOut:
    """
    Models previous output data for a Vin for a RawTransactionResult.
    """

    def __init__(
        self, value, addresses=None,
    ):
        """
        Args:
            value (float): previous output value.
            addresses (list(str)): previous output addresses. May be empty.
        """
        self.value = value
        self.addresses = addresses if addresses else []

    @staticmethod
    def parse(obj):
        """
        Parse the PrevOut from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            PrevOut: The Parsed PrevOut.
        """
        return PrevOut(
            value=obj["value"],
            addresses=obj["addresses"] if "addresses" in obj else [],
        )


class Vin:
    """
    Models a Vin for a RawTransactionResult.
    """

    def __init__(
        self,
        amountIn,
        coinbase=None,
        stakebase=None,
        txHash=None,
        vout=None,
        tree=None,
        sequence=None,
        blockHeight=None,
        blockIndex=None,
        scriptSig=None,
        prevOut=None,
    ):
        """
        Args:
            amountIn (int): The amount in for this transaction input, in coins.
            coinbase (ByteArray): The bytes of the signature script
                (coinbase txns only) or None.
            stakebase (ByteArray): The hash of the stake transaction or None.
            txHash (ByteArray): The hash of the origin transaction (non-coinbase txns
                only) or None.
            vout (int): The index of the output being redeemed from the origin
                transaction (non-coinbase txns only) or None.
            tree (int): The transaction tree of the origin transaction (non-coinbase
                txns only) or None.
            blockHeight (int): The height of the block that includes the origin
                transaction (non-coinbase txns only) or None.
            blockIndex (int): The merkle tree index of the origin transaction
                (non-coinbase txns only) or None.
            scriptSig (object): The signature script used to redeem the origin
                transaction (non-coinbase txns only) or None.
            prevOut (object): Data from the origin transaction output with index
                vout or None.
            sequence (int) The script sequence number or None.
        """
        self.amountIn = amountIn
        self.coinbase = coinbase
        self.stakebase = stakebase
        self.txHash = txHash
        self.vout = vout
        self.tree = tree
        self.sequence = sequence
        self.blockHeight = blockHeight
        self.blockIndex = blockIndex
        self.scriptSig = scriptSig
        self.prevOut = prevOut
        self.sequence = sequence

    @staticmethod
    def parse(obj):
        """
        Parse the Vin from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            Vin: The Parsed Vin.
        """
        return Vin(
            amountIn=obj["amountin"],
            coinbase=ByteArray(obj["coinbase"]) if "coinbase" in obj else None,
            stakebase=reversed(ByteArray(obj["stakebase"]))
            if "stakebase" in obj
            else None,
            txHash=reversed(ByteArray(obj["txid"])) if "txid" in obj else None,
            vout=obj.get("vout"),
            tree=obj.get("tree"),
            blockHeight=obj.get("blockheight"),
            blockIndex=obj.get("blockindex"),
            scriptSig=ScriptSig.parse(obj["scriptSig"]) if "scriptSig" in obj else None,
            prevOut=PrevOut.parse(obj["prevout"]) if "prevout" in obj else None,
            sequence=obj.get("sequence"),
        )


class ScriptSig:
    """
    Models signature data for a Vin for a RawTransactionResult.
    """

    def __init__(
        self, asm, script,
    ):
        """
        Args:
            asm (str): Disassembly of the script.
            script (ByteArray): Bytes of the script.
        """
        self.asm = asm
        self.script = script

    @staticmethod
    def parse(obj):
        """
        Parse the ScriptSig from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            ScriptSig: The Parsed ScriptSig.
        """
        ScriptSig(
            asm=obj["asm"], script=ByteArray(obj["hex"]),
        )


class Vout:
    """
    Models a Vout for a RawTransactionResult.
    """

    def __init__(
        self, value, n, version, scriptPubKey,
    ):
        """
        Args:
            value (float): The amount in DCR.
            n (int): The index of this transaction output.
            version (int): The version of the vout.
            scriptPubKey (object): The public key script used to pay coins.
        """
        self.value = value
        self.n = n
        self.version = version
        self.scriptPubKey = scriptPubKey

    @staticmethod
    def parse(obj):
        """
        Parse the Vout from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            Vout: The Parsed Vout.
        """
        return Vout(
            value=obj["value"],
            n=obj["n"],
            version=obj["version"],
            scriptPubKey=ScriptPubKeyResult.parse(obj["scriptPubKey"]),
        )


class ScriptPubKeyResult:
    """
    Models script data for a Vin for a RawTransactionResult.
    """

    def __init__(
        self, asm, Type, script=None, reqSigs=None, addresses=None, commitAmt=None,
    ):
        """
        Args:
            asm (str): Disassembly of the script.
            Type (str): The type of the script (e.g. 'pubkeyhash').
            script (ByteArray): Bytes of the script or None.
            reqSigs (int): The number of required signatures or None.
            addresses (list(str)): The Decred addresses associated with this
                script or None.
            commitAmt (float): The ticket commitment value if the script is
                for a staking commitment or None.
        """
        self.asm = asm
        self.type = Type
        self.script = script
        self.reqSigs = reqSigs
        self.addresses = addresses
        self.commitAmt = commitAmt

    @staticmethod
    def parse(obj):
        """
        Parse the ScriptPubKeyResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            ScriptPubKeyResult: The ScriptPubKeyResult.
        """
        return ScriptPubKeyResult(
            asm=obj["asm"],
            Type=obj["type"],
            script=ByteArray(obj.get("hex")),
            reqSigs=obj.get("reqSigs"),
            addresses=obj.get("addresses"),
            commitAmt=obj.get("commitAmt"),
        )


class ValidateAddressChainResult:
    """
    Models data returned by the validateAddress command.
    """

    def __init__(
        self, isValid, address=None,
    ):
        """
        Args:
            isValid (bool): Whether the address is valid.
            address (str): The address or None if not valid.
        """
        self.isValid = isValid
        self.address = address

    @staticmethod
    def parse(obj):
        """
        Parse the ValidateAddressChainResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            ValidateAddressChainResult: The ValidateAddressChainResult.
        """
        return ValidateAddressChainResult(
            isValid=obj["isvalid"], address=obj.get("address"),
        )


class VersionResult:
    """
    Models data returned by the values of a version command.
    """

    def __init__(
        self, versionString, major, minor, patch, prerelease, buildMetadata,
    ):
        """
        Args:
            versionString (str): The semver version as a string.
            major (int): The semver major.
            minor (int): The semver minor.
            patch (int): The semver patch.
            prerelease (str): Prerelease status.
            buildMetadata (str): The go version used to build the dcrd binary.
        """
        self.versionString = versionString
        self.major = major
        self.minor = minor
        self.patch = patch
        self.prerelease = prerelease
        self.buildMetadata = buildMetadata

    @staticmethod
    def parse(obj):
        """
        Parse the VersionResult from the decoded RPC response.

        Args:
            obj (dict): The decoded dcrd RPC response.

        Returns:
            VersionResult: A VersionResult object.
        """
        return VersionResult(
            versionString=obj["versionstring"],
            major=obj["major"],
            minor=obj["minor"],
            patch=obj["patch"],
            prerelease=obj["prerelease"],
            buildMetadata=obj["buildmetadata"],
        )


class WebsocketClient(Client):
    """
    A dcrd RPC client that communicates over websocket.
    """

    requestTimeout = 10  # seconds

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.waiters = {}
        self.lastErr = None
        self.closed = True
        self.connect()

    def connect(self):
        """Connect to the websocket server."""

        self.lastErr = None
        self.closed = False
        self.ws = ws.Client(
            url=makeWebsocketURL(self.url, "ws"),
            header=[f"{k}: {v}" for k, v in self.headers.items()],
            on_message=self.on_message,
            on_close=self.on_close,
            on_error=self.on_error,
            certPath=self.cert,
        )

    def close(self):
        """Close the websocket connection."""
        if self.ws:
            self.ws.close()
            self.ws = None

    def call(self, method, *params):
        """
        Call the specified method with the list of parameters. Overloaded
        Client method that routes through the ws.Client instead of http.
        """
        req = self.jsonRequest(method, params)
        q = queue.Queue(1)
        self.waiters[req.id] = q
        msg = req.json()
        self.ws.send(msg)
        try:
            resp = q.get(timeout=self.requestTimeout)
        except queue.Empty:
            log.error(f"no reply from dcrd: {msg}")
            return
        if resp.error:
            raise DecredError(f"{method} error: {resp.error}")
        return resp.result

    def on_message(self, msg):
        """Called by ws.Client when a message is received."""
        try:
            resp = Response(msg)
            q = self.waiters.get(resp.id)
            if q is None:
                log.error(f"unknown message received from dcrd: {msg}")
                return
            del self.waiters[resp.id]
            q.put(resp)

        except Exception as e:
            log.error(f"error processing websocket message: {e}")

    def on_close(self, ws):
        """Called by ws.Client when the websocket disconnects."""
        self.closed = True
        log.debug("websocket closing")

    def on_error(self, error):
        """Called by ws.Client when an error is encountered."""
        self.lastErr = error
        log.error(f"websocket error: {error}")

    def loadTxFilter(self, clear, addresses, outPoints):
        """
        Set or add to the current transaction filter.

        Args:
            clear (bool): If True, previous filter will be cleared, otherwise,
                the new filter will be combined with the old one.
            addresses list(string): Addresses of interest.
            outPoints list(msgtx.OutPoint): Outputs to look for.
        """
        ops = [
            dict(hash=op.hash.rhex(), tree=op.tree, index=op.index) for op in outPoints
        ]
        self.call("loadtxfilter", clear, addresses, ops)

    def rescan(self, blockHashes):
        """
        Scan the blocks with the currently loaded tx filter.

        Args:
            blockHashes list(ByteArray): A list of block hashes to scan.

        Returns:
            list(RescanBlock): A list of results, each representing one block
                with one or more transactions.
        """
        res = self.call("rescan", [h.rhex() for h in blockHashes])
        return [RescanBlock.parse(blk) for blk in res["discovereddata"]]


class RescanBlock:
    """
    The result from a rescan. Represents one block with one or more transaction
    that matched the transaction filter.
    """

    def __init__(self, blockHash, txs):
        """
        Args:
            blockHash (ByteArray): The block hash.
            txs list(MsgTx): The transactions that matched the tx filter.
        """
        self.hash = blockHash
        self.txs = txs

    @staticmethod
    def parse(obj):
        """
        Parse the RescanBlock from the decoded RPC response.

        Args:
            obj (dict): A dictionary from the rescan results 'discovereddata'
                list.
        """
        return RescanBlock(
            blockHash=reversed(ByteArray(obj["hash"])),
            txs=[MsgTx.deserialize(hexTX) for hexTX in obj["transactions"]],
        )
