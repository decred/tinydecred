import base64
import ssl
from tinydecred.util import tinyhttp
from tinydecred.util.encode import ByteArray
from tinydecred.pydecred.wire.msgtx import MsgTx


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

    def getBestBlock(self):
        """
        Get the height of the current best block.

        Returns:
            GetBestBlockResult: The block data.
        """
        return GetBestBlockResult.parse(self.call("getbestblock"))

    def getBlockchainInfo(self):
        """
        Get the blockchain info.

        Returns:
            GetBlockChainInfoResult: The blockchain info.
        """
        return GetBlockChainInfoResult.parse(self.call("getblockchaininfo"))

    def getRawTransaction(self, txid, verbose=False):
        """
        Returns information about a transaction given its hash.

        Args:
            txid (str): The hash of the transaction
            verbose (bool): Optional. Default=False. Specifies the transaction is
                returned as a msgtx.MsgTx object instead of a hex-encoded string

        Returns:
            msgtx.MsgTx or string: msgtx.MsgTx if verbose, hex string for the
                transaction if default.
        """
        res = self.call("getrawtransaction", txid, 0)
        return MsgTx.deserialize(ByteArray(res)) if verbose else res

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
        verbose=1,
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
            verbose (int): Optional. default=1. Specifies the transaction is returned as a JSON
                object instead of hex-encoded string.
            skip (int): Optional. Default=0. The number of leading transactions to leave out of the
                final response.
            count (int): Optional. Default=100. The maximum number of transactions to return.
            vinextra (int): Optional. Default=0. Specify that extra data from previous output will be
                returned in vin.
            reverse (bool): Optional. Default=False. Specifies that the transactions should be returned
                in reverse chronological order.
            filterAddrs (list(str)): Optional. Default=[]. Only inputs or outputs with matching
                address will be returned.

        Returns:
            list(RawTransactionResult): The RawTransactionResults.
        """
        return [
            RawTransactionsResult.parse(rawTx)
            for rawTx in self.call(
                "searchrawtransactions",
                address,
                verbose,
                skip,
                count,
                vinextra,
                reverse,
                filterAddrs if filterAddrs else [],
            )
        ]

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
            dict[str]FeeInfoResult: FeeInfoResults for the key "feeinfomempool",
            and a list of results for "feeinfoblocks", and "feeinfowindows".
        """
        info = self.call("ticketfeeinfo", blocks, windows)
        k1, k2, k3 = "feeinfomempool", "feeinfoblocks", "feeinfowindows"
        result = {}
        # k1 holds a dictionary.
        result[k1] = FeeInfoResult.parse(info[k1])
        # k2 and k3 hold arrays of dictionaries, or nothing.
        result[k2] = (
            [FeeInfoResult.parse(i) for i in info[k2]]
            if k2 in info and info[k2]
            else []
        )
        result[k3] = (
            [FeeInfoResult.parse(i) for i in info[k3]]
            if k3 in info and info[k2]
            else []
        )
        return result

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
            dict[str]FeeInfoResult: FeeInfoResults for the keys "feeinfomempool"
                and "feeinforange" or None, and a list of FeeInfoResults for "feeinfoblocks".
        """
        info = self.call("txfeeinfo", blocks, rangeStart, rangeEnd)
        k1, k2, k3 = "feeinfomempool", "feeinfoblocks", "feeinforange"
        result = {}
        # k1 and k3 hold a dictionary.
        result[k1] = FeeInfoResult.parse(info[k1])
        result[k3] = FeeInfoResult.parse(info[k3]) if k3 in info else None
        # k2 holds an array of dictionaries, or nothing.
        result[k2] = (
            [FeeInfoResult.parse(i) for i in info[k2]]
            if k2 in info and info[k2]
            else []
        )
        return result

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
                coins as a JSON object
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
            id (str): Unique identifier of this agenda.
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
            if obj["agendas"]
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


class RawTransactionsResult:
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
            vin (list(object)): The transaction inputs as JSON objects.
            vout (list(object)): The transaction outputs as JSON objects.
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
        return RawTransactionsResult(
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
            value=obj["value"], addresses=obj["addresses"] if obj["addresses"] else [],
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
                transaction as a JSON object (non-coinbase txns only) or None.
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
            scriptPubKey (object): The public key script used to pay coins as a
                JSON object.
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
