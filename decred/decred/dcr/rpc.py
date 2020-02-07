"""
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

import base64
import ssl

from decred.util import tinyhttp
from decred.util.encode import ByteArray

from .wire.msgblock import BlockHeader
from .wire.msgtx import MsgTx


class Client(object):
    """
    The Client communicates with the blockchain RPC API.
    """

    def __init__(self, host, user, pw, cert=None):
        """
        Args:
            host (str): The RPC address.
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
        self.host = host
        self.sslContext = None
        if cert:
            self.sslContext = ssl.SSLContext()
            self.sslContext.load_verify_locations(cert)

    def call(self, method, *params):
        """
        Call the specified remote method with the a list of parameters.
        """
        data = {"jsonrpc": "2.0", "id": 0, "method": method, "params": params}
        res = tinyhttp.post(
            self.host, data, headers=self.headers, context=self.sslContext
        )
        if not isinstance(res, dict):
            raise AssertionError(
                "rpc.Client call result of unexpected type %s" % type(res)
            )
        if "error" in res and res["error"]:
            raise Exception("%s error: %r" % (method, res["error"]))
        return res["result"]

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
        mask = int(self.call("existsaddresses", addresses), 16)
        return [bool(mask & 1 << n) for n in range(len(addresses))]

    def existsExpiredTickets(self, txHashes):
        """
        Test for the existence of the provided tickets in the expired ticket map.

        Args:
            txHashes (list(str):) Array of hashes to check.

        Returns:
            list(bool): Bool list showing if ticket exists in the expired ticket
                database or not.
        """
        mask = int(self.call("existsexpiredtickets", txHashes), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def existsLiveTicket(self, txHash):
        """
        Test for the existence of the provided ticket

        Args:
            txHash (str): The ticket hash to check.

        Returns:
            bool: True if address exists in the live ticket database.
        """
        return self.call("existsliveticket", txHash)

    def existsLiveTickets(self, txHashes):
        """
        Test for the existence of the provided tickets in the live ticket map.

        Args:
            txHashes (list(str)): Array of hashes to check.

        Returns:
            list(bool): Bool list showing if ticket exists in the live ticket
                database or not.
        """
        mask = int(self.call("existslivetickets", txHashes), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def existsMempoolTxs(self, txHashes):
        """
        Test for the existence of the provided txs in the mempool.

        Args:
            txHashes (list(str)): Array of hashes to check.

        Returns:
            list(bool): Bool list showing if txs exist in the mempool or not.
        """
        mask = int(self.call("existsmempooltxs", txHashes), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def existsMissedTickets(self, txHashes):
        """
        Test for the existence of the provided tickets in the missed ticket map.

        Args:
            txHashes (list(bool)):Array of hashes to check.

        Returns:
            list(bool): Bool list showing if the ticket exists in the missed
                ticket database or not.
        """
        mask = int(self.call("existsmissedtickets", txHashes), 16)
        return [bool(mask & 1 << n) for n in range(len(txHashes))]

    def generate(self, numBlocks):
        """
        Generates a set number of blocks (simnet or regtest only) and returns a
        JSON array of their hashes.

        Args:
            numBlocks (int): Number of blocks to generate.

        Returns:
            list(str): The hashes, in order, of blocks generated by the call.
        """
        return self.call("generate", numBlocks)

    def getAddedNodeInfo(self, dns, node=None):
        """
        Returns information about manually added (persistent) peers.

        Args:
            dns (bool): Specifies whether the returned data is a JSON object
                including DNS and connection information, or just a list of
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
            str: The hex-encoded block hash
        """
        return self.call("getbestblockhash")

    def getBlock(self, blockHash, verbose=True, verboseTx=False):
        """
        Returns information about a block given its hash.

        Args:
            blockHash (str): The hash of the block.
            verbose (bool): Optional. Default=True. Specifies the block is
                returned as a JSON object instead of hex-encoded string.
            verboseTx (bool): Optional. Default=False. Specifies that each
                transaction is returned as a JSON object and only applies if
                the verbose flag is true (dcrd extension).

        Returns:
            str or GetBlockVerboseResult: GetBlockVerboseResult if verbose else
                Hex-encoded bytes of the serialized block.
        """
        res = self.call("getblock", blockHash, verbose, verboseTx)
        return GetBlockVerboseResult.parse(res) if verbose else res

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
        s = self.call("getblockhash", index)
        return reversed(ByteArray(s))

    def getBlockHeader(self, blockHash, verbose=True):
        """
        Returns information about a block header given its hash.

        Args:
            blockHash (str): The hash of the block.
            verbose (bool): Optional. Default=True. Specifies the block
                header is returned as a GetBlockHeaderVerboseResult instead of
                a msgblock.BlockHeader.

        Returns:
            GetBlockHeaderVerboseResult or msgblock.BlockHeader: The
                GetBlockHeaderVerboseResult if vebose or the msgblock.BlockHeader
                otherwise.
        """
        res = self.call("getblockheader", blockHash, verbose)
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
            blockHash (str): The block hash of the filter being queried.
            filterType (str): The type of committed filter to return.

        Returns:
            str: The committed filter serialized with the N value and encoded
                as a hex string.
        """
        return self.call("getcfilter", blockHash, filterType)

    def getCFilterHeader(self, blockHash, filterType):
        """
        Returns the filter header hash committing to all filters in the chain up
        through a block.

        Args:
            blockHash (str): The block hash of the filter header being queried.
            filterType (str): The type of committed filter to return the
                header commitment for.

        Returns:
            str: The filter header commitment hash.
        """
        return self.call("getcfilterheader", blockHash, filterType)

    def getCFilterV2(self, blockHash):
        """
        Returns the version 2 block filter for the given block along with a
            proof that can be used to prove the filter is committed to by the
            block header.

        Args:
            blockHash (str): The block hash of the filter to retrieve.

        Returns:
            GetCFilterV2Result: The version 2 block filter.
        """
        return GetCFilterV2Result.parse(self.call("getcfilterv2", blockHash))

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
            blockLocators (list(str)): Array of block locator hashes.
                Headers are returned starting from the first known hash in this
                list.
            hashStop (str): Block hash to stop including block headers for.
                Set to zero to get as many blocks as possible.

        Returns:
            list(str): Serialized block headers of all located blocks,
                limited to some arbitrary maximum number of hashes (currently
                2000, which matches the wire protocol headers message, but this
                is not guaranteed).
        """
        return self.call("getheaders", blockLocators, hashStop)["headers"]

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
        Returns the estimated network hashes per second for the block heights provided by the parameters.

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
            list(str) or dict[str]GetRawMempoolVerboseResult: Array of
                transaction hashes if not verbose. A dict of transaction hashes
                to GetRawMempoolVerboseResult if verbose.
        """
        res = self.call("getrawmempool", verbose, *([txtype] if txtype else []))
        return (
            {k: GetRawMempoolVerboseResult.parse(v) for k, v in res.items()}
            if verbose
            else res
        )

    def getRawTransaction(self, txid, verbose=False):
        """
        Returns information about a transaction given its hash.

        Args:
            txid (str): The hash of the transaction.
            verbose (bool): Optional. Default=False. Specifies the transaction is
                returned as a RawTransactionResult instead of a msgtx.MsgTx.

        Returns:
            msgtx.MsgTx or RawTransactionResult: RawTransactionResult if
                verbose, msgtx.MsgTx for the transaction if default.
        """
        verb = 1 if verbose else 0
        res = self.call("getrawtransaction", txid, verb)
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
            blockHash (str) The start block hash.
            count (int) The number of blocks that will be returned.

        Returns:
            list(GetStakeVersionsResult): Array of stake versions per block.
        """
        return [
            GetStakeVersionsResult.parse(ver)
            for ver in self.call("getstakeversions", blockHash, count)["stakeversions"]
        ]

    def getTicketPoolValue(self):
        """
        Return the current value of all locked funds in the ticket pool.

        Returns:
            float: Total value of ticket pool
        """
        return self.call("getticketpoolvalue")

    def getTxOut(self, txid, vout, includeMempool=True):
        """
        Returns information about an unspent transaction output.

        Args:
            txid (str): The hash of the transaction
            vout (int): The index of the output
            includeMempool (bool): Optional. Default=True. Include the mempool
                when true

        Returns:
            GetTxOutResult: The utxo information.
        """
        return GetTxOutResult.parse(self.call("gettxout", txid, vout, includeMempool))

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
            data (str): Optional. Default=None. Hex-encoded data to check

        Returns:
            GetWorkResult or bool: If data is not provided, returns GetWorkResult,
                else returns whether or not the solved data is valid and was
                added to the chain
        """
        res = self.call("getwork", *([data] if data else []))
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
            list(str): List of live tickets.
        """
        return self.call("livetickets")["tickets"]

    def missedTickets(self):
        """
        Returns missed ticket hashes from the ticket database.

        Returns:
            list(str): List of missed tickets.
        """
        return self.call("missedtickets")["tickets"]

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
        self.call(
            "node", self, subcmd, target, *([connectSubCmd] if connectSubCmd else [])
        )

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
        return [RawTransactionResult.parse(rawTx) for rawTx in res] if verbose else res

    def sendRawTransaction(self, msgTx, allowHighFees=False):
        """
        Submits the serialized, hex-encoded transaction to the local peer and
        relays it to the network.

        Args:
            msgTx (object): msgtx.MsgTx signed transaction.
            allowHighFees (bool): Optional. Default=False. Whether or not to allow insanely high fees
                (dcrd does not yet implement this parameter, so it has no effect).

        Returns:
            bytes-like: The hash of the transaction.
        """
        txid = self.call("sendrawtransaction", msgTx.txHex(), allowHighFees)
        return reversed(ByteArray(txid))

    def setGenerate(self, generate, numCPUs=-1):
        """
        Set the server to generate coins (mine) or not.

        Args:
            generate (bool): Use True to enable generation, False to disable it.
            numCPUs (int): Optional. Default=-1. The number of processors (cores) to limit
                generation to or -1 for default.
        """
        self.call("setgenerate", generate, numCPUs)

    def stop(self):
        """
        Shutdown dcrd.

        Returns:
            str: 'dcrd stopping.'
        """
        return self.call("stop")

    def submitBlock(self, hexBlock, options=None):
        """
        Attempts to submit a new serialized, hex-encoded block to the network.

        Args:
            hexBlock (str): Serialized, hex-encoded block.
            options: Optional. Default={}. This parameter is currently ignored.

        Returns:
            str: The reason the block was rejected if rejected or None.
        """
        return self.call("submitblock", hexBlock, options if options else {})

    def ticketFeeInfo(self, blocks=0, windows=0):
        """
        Get various information about ticket fees from the mempool, blocks, and
        difficulty windows (units: DCR/kB).

        Args:
            blocks (int): Optional. Default=0. The number of blocks, starting from the
                chain tip and descending, to return fee information about.
            windows (int): Optional. Default=0. The number of difficulty windows to return
                ticket fee information about.

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
            list(str): Tickets owned by the specified address.
        """
        return self.call("ticketsforaddress", addr)["tickets"]

    def ticketVWAP(self, start=None, end=None):
        """
        Calculate the volume weighted average price of tickets for a range of
        blocks (default: full PoS difficulty adjustment depth).

        Args:
            start (int): Optional. Default=None. The start height to begin calculating the VWAP from.
            end (int): Optional. Default=None. The end height to begin calculating the VWAP from.

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
            dict[str]VersionResult: dcrd's version info with keys "dcrd" and "dcrdjsonrpcapi".
        """
        return {k: VersionResult.parse(v) for k, v in self.call("version").items()}


def get(k, obj):
    """
    Helper method to check for nil keys and set those values to None.

    Args:
        k (str): dict key
        obj (dict): the dict to search

    Returns:
        object: the thing found at k or None.
    """
    return obj[k] if k in obj else None


class GetBlockVerboseResult:
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
        nextHash,
        tx,
        rawTx,
        sTx,
        rawSTx,
    ):
        """
        Args:
            blockHash (str): The hash of the block (same as provided).
            confirmations (int): The number of confirmations.
            size (int): The size of the block.
            height (int): The height of the block in the block chain.
            version (int): The block version.
            merkleRoot (str): Root hash of the merkle tree.
            stakeRoot (str): The block's sstx hashes the were included.
            time (int): The block time in seconds since 1 Jan 1970 GMT.
            nonce (int): The block nonce.
            voteBits (int): The block's voting results.
            finalState (str): The block's finalstate.
            voters (int): The number votes in the block.
            freshStake (int): The number of new tickets in the block.
            revocations (int): The number of revocations in the block.
            poolSize (int): The size of the live ticket pool.
            bits (str): The bits which represent the block difficulty.
            sBits (float): The stake difficulty of theblock.
            extraData (str): Extra data field for the requested block.
            stakeVersion (int): Stake Version of the block.
            difficulty (float): The proof-of-work difficulty as a multiple of
                the minimum difficulty.
            chainWork (str): The total number of hashes expected to produce
                the chain up to the block in hex.
            previousHash (str): The hash of the previous block.
            nextHash (str): The hash of the next block (only if there is one).
            tx (list(str)): The transaction hashes (only when verboseTx=false).
            rawTx (list(RawTransactionResult)): The transactions as JSON objects
                (only when verboseTx=true).
            sTx (list(str)): The block's sstx hashes the were included (only
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
        self.tx = tx
        self.rawTx = rawTx
        self.sTx = sTx
        self.rawSTx = rawSTx

    @staticmethod
    def parse(obj):
        return GetBlockVerboseResult(
            blockHash=obj["hash"],
            confirmations=obj["confirmations"],
            size=obj["size"],
            height=obj["height"],
            version=obj["version"],
            merkleRoot=obj["merkleroot"],
            stakeRoot=obj["stakeroot"],
            time=obj["time"],
            nonce=obj["nonce"],
            voteBits=obj["votebits"],
            finalState=obj["finalstate"],
            voters=obj["voters"],
            freshStake=obj["freshstake"],
            revocations=obj["revocations"],
            poolSize=obj["poolsize"],
            bits=obj["bits"],
            sBits=obj["sbits"],
            extraData=obj["extradata"],
            stakeVersion=obj["stakeversion"],
            difficulty=obj["difficulty"],
            chainWork=obj["chainwork"],
            previousHash=obj["previousblockhash"],
            nextHash=get("nextblockhash", obj),
            tx=get("tx", obj),
            rawTx=[RawTransactionResult.parse(tx) for tx in obj["rawtx"]]
            if "rawtx" in obj
            else [],
            sTx=get("stx", obj),
            rawSTx=[RawTransactionResult.parse(stx) for stx in obj["rawstx"]]
            if "rawstx" in obj
            else [],
        )


class GetAddedNodeInfoResultAddr:
    """
    GetAddedNodeInfoResultAddr models the data of the addresses portion of the
    getaddednodeinfo command.
    """

    def __init__(
        self, address, connected,
    ):
        """
        address (str): The ip address for this DNS entry.
        connected (str): The connection 'direction' (inbound/outbound/false).
        """
        self.address = address
        self.connected = connected

    @staticmethod
    def parse(obj):
        return GetAddedNodeInfoResultAddr(
            address=obj["address"], connected=obj["connected"],
        )


class GetAddedNodeInfoResult:
    """getaddednodeinforesult"""

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
        return GetAddedNodeInfoResult(
            addedNode=obj["addednode"],
            connected=get("connected", obj),
            addresses=[
                GetAddedNodeInfoResultAddr.parse(addr) for addr in obj["addresses"]
            ]
            if "addresses" in obj
            else [],
        )


class GetChainTipsResult:
    def __init__(
        self, height, blockHash, branchLen, status,
    ):
        """
        Args:
            height (int): The height of the chain tip.
            blockHash (str): The block hash of the chain tip.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetChainTipsResult: The GetChainTipsResult.
        """
        return GetChainTipsResult(
            height=obj["height"],
            blockHash=obj["hash"],
            branchLen=obj["branchlen"],
            status=obj["status"],
        )


class GetBlockSubsidyResult:
    """getblocksubsidyresult"""

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
            obj (object): The decoded dcrd RPC response.

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
    def __init__(
        self, blockHash, data, proofIndex, proofHashes,
    ):
        """
        Args:
            blockHash (str): The block hash for which the filter includes data.
            data (str): Hex-encoded bytes of the serialized filter.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetCFilterV2Result: The GetCFilterV2Result.
        """
        return GetCFilterV2Result(
            blockHash=obj["blockhash"],
            data=obj["data"],
            proofIndex=obj["proofindex"],
            proofHashes=obj["proofhashes"],
        )


class GetBlockHeaderVerboseResult:
    """getblockheaderverboseresult"""

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
            blockHash (str): The hash of the block (same as provided).
            confirmations (int): The number of confirmations.
            version (int): The block version.
            merkleRoot (str): The merkle root of the regular transaction tree.
            stakeRoot (str): The merkle root of the stake transaction tree.
            voteBits (int): The vote bits.
            finalState (str): The final state value of the ticket pool.
            voters (int): The number of votes in the block.
            freshStake (int): The number of new tickets in the block.
            revocations (int): The number of revocations in the block.
            poolSize (int): The size of the live ticket pool.
            bits (str): The bits which represent the block difficulty.
            sBits (float): The stake difficulty in coins.
            height (int): The height of the block in the block chain.
            size (int): The size of the block in bytes.
            time (int): The block time in seconds since 1 Jan 1970 GMT.
            nonce (int): The block nonce.
            extraData (str): Extra data field for the requested block.
            stakeVersion (int): The stake version of the block.
            difficulty (float): The proof-of-work difficulty as a multiple of
                the minimum difficulty.
            chainWork (str): The total number of hashes expected to produce
                the chain up to the block in hex.
            previousHash (str): The hash of the previous block or None.
            nextHash (str): The hash of the next block or None.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetBlockHeaderVerboseResult: The GetBlockHeaderVerboseResult.
        """
        return GetBlockHeaderVerboseResult(
            blockHash=obj["hash"],
            confirmations=obj["confirmations"],
            version=obj["version"],
            merkleRoot=obj["merkleroot"],
            stakeRoot=obj["stakeroot"],
            voteBits=obj["votebits"],
            finalState=obj["finalstate"],
            voters=obj["voters"],
            freshStake=obj["freshstake"],
            revocations=obj["revocations"],
            poolSize=obj["poolsize"],
            bits=obj["bits"],
            sBits=obj["sbits"],
            height=obj["height"],
            size=obj["size"],
            time=obj["time"],
            nonce=obj["nonce"],
            extraData=obj["extradata"],
            stakeVersion=obj["stakeversion"],
            difficulty=obj["difficulty"],
            chainWork=obj["chainwork"],
            previousHash=get("previoushash", obj),
            nextHash=get("nexthash", obj),
        )


class GetRawMempoolVerboseResult:
    """getrawmempoolverboseresult"""

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
            depends (list(str)): Unconfirmed transactions used as inputs for
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
            obj (object): The decoded dcrd RPC response.

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
            depends=obj["depends"],
        )


class GetPeerInfoResult:
    """getpeerinforesult"""

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
            services (str): Services bitmask which represents the services
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetPeerInfoResult: The GetPeerInfoResult.
        """
        return GetPeerInfoResult(
            nodeID=obj["id"],
            addr=obj["addr"],
            services=obj["services"],
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
            addrLocal=get("addrlocal", obj),
            pingWait=get("pingwait", obj),
            currentHeight=get("currentheight", obj),
        )


class LocalAddressesResult:
    """
    LocalAddressesResult models the localaddresses data from the getnetworkinfo
    command.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            LocalAddressesResult: The LocalAddressesResult.
        """
        return LocalAddressesResult(
            address=obj["address"], port=obj["port"], score=obj["score"],
        )


class NetworksResult:
    """
    NetworksResult models the networks data from the getnetworkinfo command.
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
            obj (object): The decoded dcrd RPC response.

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
    """getnetworkinforesult"""

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
            localAddresses (list(LocalAddressesResult)): An array of objects.
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
            obj (object): The decoded dcrd RPC response.

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
    """getnettotalsresult"""

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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetNetTotalsResult: The GetNetTotalsResult.
        """
        return GetNetTotalsResult(
            totalBytesRecv=obj["totalbytesrecv"],
            totalBytesSent=obj["totalbytessent"],
            timeMillis=obj["timemillis"],
        )


class GetMiningInfoResult:
    """getmininginforesult"""

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
            obj (object): The decoded dcrd RPC response.

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
    """getmempoolinforesult"""

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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetMempoolInfoResult: The GetMempoolInfoResult.
        """
        return GetMempoolInfoResult(size=obj["size"], Bytes=obj["bytes"])


class InfoChainResult:
    """infochainresult"""

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
            obj (object): The decoded dcrd RPC response.

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
    """getworkresult"""

    def __init__(
        self, data, target,
    ):
        """
        Args:
            data (str): Hex-encoded block data.
            target (str): Hex-encoded little-endian hash target.
        """
        self.data = data
        self.target = target

    @staticmethod
    def parse(obj):
        """
        Parse the GetWorkResult from the decoded RPC response.

        Args:
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetWorkResult: The GetWorkResult.
        """
        return GetWorkResult(data=obj["data"], target=obj["target"])


class GetTxOutResult:
    """gettxoutresult"""

    def __init__(
        self, bestBlock, confirmations, value, scriptPubKey, version, coinbase,
    ):
        """
        Args:
            bestBlock (str): The block hash that contains the transaction
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetTxOutResult: The GetTxOutResult.
        """
        return GetTxOutResult(
            bestBlock=obj["bestblock"],
            confirmations=obj["confirmations"],
            value=obj["value"],
            scriptPubKey=ScriptPubKeyResult.parse(obj["scriptPubKey"]),
            version=obj["version"],
            coinbase=obj["coinbase"],
        )


class Choice:
    """
    Choice models an individual choice inside an Agenda.
    """

    def __init__(
        self, choiceID, description, bits, isAbstain, isNo, count, progress,
    ):
        """
        Args:
            choiceID (str): Unique identifier of this choice.
            description (str): Description of this choice.
            bits (int): Bits that identify this choice.
            isAbstain (bool): This choice is to abstain from change.
            isNo (bool): Hard no choice (1 and only 1 per agenda).
            count (int): How many votes received.
            progress (float): Progress of the overall count.
        """
        self.choiceID = choiceID
        self.description = description
        self.bits = bits
        self.isAbstain = isAbstain
        self.isNo = isNo
        self.count = count
        self.progress = progress

    @staticmethod
    def parse(obj):
        """
        Parse the Choice from the decoded RPC response.

        Args:
            obj (object): The decoded dcrd RPC response.

        Returns:
            Choice: The parsed Choice.
        """
        return Choice(
            choiceID=obj["id"],
            description=obj["description"],
            bits=obj["bits"],
            isAbstain=obj["isabstain"],
            isNo=obj["isno"],
            count=obj["count"],
            progress=obj["progress"],
        )


class Agenda:
    """
    Agenda models an individual agenda including its choices.
    """

    def __init__(
        self,
        agendaID,
        description,
        mask,
        startTime,
        expireTime,
        status,
        quorumProgress,
        choices,
    ):
        """
        Args:
            AgendaID (str): Unique identifier of this agenda.
            description (str): Description of this agenda.
            mask (int): Agenda mask.
            startTime (int): Time agenda becomes valid.
            expireTime (int): Time agenda becomes invalid.
            status (str): Agenda status.
            quorumProgress (float): Progress of quorum reached.
            choices list(Choice): All choices in this agenda.
        """
        self.agendaID = agendaID
        self.description = description
        self.mask = mask
        self.startTime = startTime
        self.expireTime = expireTime
        self.status = status
        self.quorumProgress = quorumProgress
        self.choices = choices

    @staticmethod
    def parse(obj):
        """
        Parse the Agenda from the decoded RPC response.

        Args:
            obj (object): The decoded dcrd RPC response.

        Returns:
            Agenda: The parsed Agenda info.
        """
        return Agenda(
            agendaID=obj["id"],
            description=obj["description"],
            mask=obj["mask"],
            startTime=obj["starttime"],
            expireTime=obj["expiretime"],
            status=obj["status"],
            quorumProgress=obj["quorumprogress"],
            choices=[Choice.parse(choice) for choice in obj["choices"]],
        )


class GetVoteInfoResult:
    """getvoteinfo"""

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
        hash (str): The hash of the current height block.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetVoteInfoResult: The GetVoteInfoResult.
        """
        return GetVoteInfoResult(
            currentHeight=obj["currentheight"],
            startHeight=obj["startheight"],
            endHeight=obj["endheight"],
            blockHash=obj["hash"],
            voteVersion=obj["voteversion"],
            quorum=obj["quorum"],
            totalVotes=obj["totalvotes"],
            agendas=[Agenda.parse(agenda) for agenda in obj["agendas"]]
            if "agendas" in obj
            else [],
        )


class VersionBits:
    """
    VersionBits models a generic version:bits tuple.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            VersionBits: The parsed VersionBits.
        """
        return VersionBits(version=obj["version"], bits=obj["bits"])


class GetStakeVersionsResult:
    """getstakeversionsresult"""

    def __init__(
        self, blockHash, height, blockVersion, stakeVersion, votes,
    ):
        """
        Args:
            blockHash (str): Hash of the block.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            StakeVersionsResult: The StakeVersionsResult.
        """
        return GetStakeVersionsResult(
            blockHash=obj["hash"],
            height=obj["height"],
            blockVersion=obj["blockversion"],
            stakeVersion=obj["stakeversion"],
            votes=[VersionBits.parse(vote) for vote in obj["votes"]],
        )


class VersionCount:
    """
    VersionCount models a generic version:count tuple.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            VersionCount: The parsed VersionCount.
        """
        return VersionCount(version=obj["version"], count=obj["count"])


class VersionInterval:
    """
    VersionInterval models a version count for an interval.
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
            obj (object): The decoded dcrd RPC response.

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
    """getstakeversioninforesult"""

    def __init__(
        self, currentHeight, blockHash, intervals,
    ):
        """
        Args:
            currentHeight (int): Top of the chain height.
            hash (str): Top of the chain hash.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetStakeVersionInfoResult: The GetStakeVersionInfoResult.
        """
        return GetStakeVersionInfoResult(
            currentHeight=obj["currentheight"],
            blockHash=obj["hash"],
            intervals=[VersionInterval.parse(ver) for ver in obj["intervals"]],
        )


class GetStakeDifficultyResult:
    """getstakedifficultyresult"""

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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetStakeDifficultyResult: The GetStakeDifficultyResult.
        """
        return GetStakeDifficultyResult(
            currentStakeDifficulty=obj["current"], nextStakeDifficulty=obj["next"],
        )


class FeeInfoResult:
    """
    Models the data returned from ticketFeeInfo and txFeeInfo.
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
            obj (object): The decoded dcrd RPC response.

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
            height=get("height", obj),
            startHeight=get("startheight", obj),
            endHeight=get("endheight", obj),
        )


class TicketFeeInfoResult:
    """ticketfeeinforesult"""

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
            obj (object): The decoded dcrd RPC response.

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
    """txfeeinforesult"""

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
            obj (object): The decoded dcrd RPC response.

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


class GetBestBlockResult(object):
    """getbestblockhash"""

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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetBestBlockResult: The GetBestBlockResult.
        """
        blockHash = reversed(ByteArray(obj["hash"]))
        return GetBestBlockResult(blockHash=blockHash, height=obj["height"])


class GetBlockChainInfoResult(object):
    """getblockchaininfo"""

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
            bestBlockHash (str): The block hash of the current best chain
                tip.
            difficultyRatio (float): The current proof-of-work difficulty as
                a multiple of the minimum difficulty.
            verificationProgress (float): The chain verification progress
                estimate.
            chainWork (str): Hex encoded total work done for the chain.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            GetBlockChainInfoResult: The GetBlockChainInfoResult.
        """
        return GetBlockChainInfoResult(
            chain=obj["chain"],
            blocks=obj["blocks"],
            headers=obj["headers"],
            syncHeight=obj["syncheight"],
            bestBlockHash=obj["bestblockhash"],
            difficultyRatio=obj["difficultyratio"],
            verificationProgress=obj["verificationprogress"],
            chainWork=obj["chainwork"],
            initialBlockDownload=obj["initialblockdownload"],
            maxBlockSize=obj["maxblocksize"],
            deployments={k: AgendaInfo.parse(v) for k, v in obj["deployments"].items()},
        )


class AgendaInfo(object):
    """
    AgendaInfo provides an overview of an agenda in a consensus deployment.
    """

    def __init__(
        self, status, since, startTime, expireTime,
    ):
        """
        Args:
            status (str): One of "defined", "started", "lockedin", "active",
                "failed".
            since (int): Height of last state change.
            startTime (int): Start time.
            expireTime (int): End time.
        """
        self.status = status
        self.since = since
        self.startTime = startTime
        self.expireTime = expireTime

    @staticmethod
    def parse(obj):
        """
        Parse the AgendaInfo from the decoded RPC response.

        Args:
            obj (object): The decoded dcrd RPC response.

        Returns:
            AgendaInfo: The AgendaInfo.
        """
        return AgendaInfo(
            status=obj["status"],
            since=obj["since"] if "since" in obj else 0,
            startTime=obj["starttime"],
            expireTime=obj["expiretime"],
        )


class RawTransactionResult:
    """searchrawtransactions"""

    def __init__(
        self,
        txid,
        version,
        lockTime,
        expiry,
        vin,
        vout,
        txHex=None,
        blockHash=None,
        blockHeight=None,
        blockIndex=None,
        confirmations=None,
        time=None,
        blockTime=None,
    ):
        """
        Args:
            txid (str):  The hash of the transaction.
            version (int): The transaction version.
            locktime (int): The transaction lock time.
            expiry (int): The transacion expiry.
            vin (list(object)): The transaction inputs.
            vout (list(object)): The transaction outputs.
            txHex (str): Hex-encoded transaction or None.
            blockHash (str): The hash of the block the contains the transaction or None.
            blockHeight (int): The height of the block that contains the transaction or None.
            blockIndex (int): The index within the array of transactions
                contained by the block or None.
            confirmations (int): Number of confirmations of the block or None.
            time (int): Transaction time in seconds since 1 Jan 1970 GMT or None.
            blockTime (int): Block time in seconds since the 1 Jan 1970 GMT or None.
        """
        self.txid = txid
        self.version = version
        self.lockTime = lockTime
        self.expiry = expiry
        self.vin = vin
        self.vout = vout
        self.txHex = txHex
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            RawTransactionResult: The RawTransactionResult.
        """
        return RawTransactionResult(
            txid=obj["txid"],
            version=obj["version"],
            lockTime=obj["locktime"],
            expiry=obj["expiry"],
            vin=[Vin.parse(vin) for vin in obj["vin"]],
            vout=[Vout.parse(vout) for vout in obj["vout"]],
            txHex=get("hex", obj),
            blockHash=get("blockhash", obj),
            blockHeight=get("blockheight", obj),
            blockIndex=get("blockindex", obj),
            confirmations=get("confirmations", obj),
            time=get("time", obj),
            blockTime=get("blocktime", obj),
        )


class PrevOut:
    """
    PrevOut represents previous output for an input Vin.
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            PrevOut: The Parsed PrevOut.
        """
        return PrevOut(
            value=obj["value"],
            addresses=obj["addresses"] if "addresses" in obj else [],
        )


class Vin:
    """
    Vin models parts of the tx data.  It is defined separately since
    getrawtransaction, decoderawtransaction, and searchrawtransaction use the
    same structure.
    """

    def __init__(
        self,
        amountIn,
        coinbase=None,
        stakebase=None,
        txid=None,
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
            coinbase (str): The hex-encoded bytes of the signature script
                (coinbase txns only) or None.
            stakebase (str): The hash of the stake transaction or None.
            txid (str): The hash of the origin transaction (non-coinbase txns
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
        self.txid = txid
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
            obj (object): The decoded dcrd RPC response.

        Returns:
            Vin: The Parsed Vin.
        """
        Vin(
            amountIn=obj["amountin"],
            coinbase=get("coinbase", obj),
            stakebase=get("stakebase", obj),
            txid=get("txid", obj),
            vout=get("vout", obj),
            tree=get("tree", obj),
            blockHeight=get("blockheight", obj),
            blockIndex=get("blockindex", obj),
            scriptSig=ScriptSig.parse(obj["scriptSig"]) if "scriptSig" in obj else None,
            prevOut=PrevOut.parse(obj["prevout"]) if "prevout" in obj else None,
            sequence=get("sequence", obj),
        )


class ScriptSig:
    """
    ScriptSig models a signature script.  It is defined separately since it only
    applies to non-coinbase.  Therefore the field in the Vin structure needs
    to be a pointer.
    """

    def __init__(
        self, asm, scriptHex,
    ):
        """
        Args:
            asm (str): Disassembly of the script.
            scriptHex (str): Hex-encoded bytes of the script.
        """
        self.asm = asm
        self.scriptHex = scriptHex

    @staticmethod
    def parse(obj):
        """
        Parse the ScriptSig from the decoded RPC response.

        Args:
            obj (object): The decoded dcrd RPC response.

        Returns:
            ScriptSig: The Parsed ScriptSig.
        """
        ScriptSig(
            asm=obj["asm"], scriptHex=obj["hex"],
        )


class Vout:
    """
    Vout models parts of the tx data.  It is defined separately since both
    getrawtransaction and decoderawtransaction use the same structure.
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
            obj (object): The decoded dcrd RPC response.

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
    ScriptPubKeyResult models the scriptPubKey data of a tx script.  It is
    defined separately since it is used by multiple commands.
    """

    def __init__(
        self, asm, Type, scriptHex=None, reqSigs=None, addresses=None, commitAmt=None,
    ):
        """
        Args:
            asm (str): Disassembly of the script.
            Type (str): The type of the script (e.g. 'pubkeyhash').
            scriptHex (str): Hex-encoded bytes of the script or None.
            reqSigs (int): The number of required signatures or None.
            addresses (list(str)): The Decred addresses associated with this
                script or None.
            commitAmt (float): The ticket commitment value if the script is
                for a staking commitment or None.
        """
        self.asm = asm
        self.type = Type
        self.scriptHex = scriptHex
        self.reqSigs = reqSigs
        self.addresses = addresses
        self.commitAmt = commitAmt

    @staticmethod
    def parse(obj):
        """
        Parse the ScriptPubKeyResult from the decoded RPC response.

        Args:
            obj (object): The decoded dcrd RPC response.

        Returns:
            ScriptPubKeyResult: The ScriptPubKeyResult.
        """
        return ScriptPubKeyResult(
            asm=obj["asm"],
            Type=obj["type"],
            scriptHex=get("hex", obj),
            reqSigs=get("reqSigs", obj),
            addresses=get("addresses", obj),
            commitAmt=get("commitAmt", obj),
        )


class ValidateAddressChainResult:
    """validateaddress"""

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
            obj (object): The decoded dcrd RPC response.

        Returns:
            ValidateAddressChainResult: The ValidateAddressChainResult.
        """
        return ValidateAddressChainResult(
            isValid=obj["isvalid"], address=get("address", obj),
        )


class VersionResult:
    """
    VersionResult provides a data structure to store version information.
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
            obj (object): The decoded dcrd RPC response.

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
