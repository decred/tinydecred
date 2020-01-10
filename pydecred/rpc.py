import base64
import ssl
from tinydecred.util import tinyhttp
from tinydecred.crypto.bytearray import ByteArray


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
        assert isinstance(res, dict)
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

    def searchRawTransactions(
        self,
        address,
        verbose=1,
        skip=0,
        count=100,
        vinextra=0,
        reverse=False,
        filteraddrs=[],
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
            filteraddrs (list(str)): Optional. Default=[]. Only inputs or outputs with matching
                address will be returned.

        Returns:
            list(SearchRawTransactionResult): The SearchRawTransactionResults.
        """
        return [
            SearchRawTransactionsResult.parse(rawTx)
            for rawTx in self.call(
                "searchrawtransactions",
                address,
                verbose,
                skip,
                count,
                vinextra,
                reverse,
                filteraddrs,
            )
        ]

    def sendRawTransaction(self, msgTx, allowhighfees=False):
        """
        Submits the serialized, hex-encoded transaction to the local peer and
        relays it to the network.

        Args:
            msgTx (object): msgtx.MsgTx signed transaction.
            allowhighfees (bool): Optional. Default=False. Whether or not to allow insanely high fees
                (dcrd does not yet implement this parameter, so it has no effect).

        Returns:
            bytes-like: The hash of the transaction.
        """
        txid = self.call("sendrawtransaction", msgTx.txHex(), allowhighfees)
        return reversed(ByteArray(txid))

    def setGenerate(self, generate, genproclimit=-1):
        """
        Set the server to generate coins (mine) or not.

        Args:
            generate (bool): Use True to enable generation, False to disable it.
            genproclimit (int): Optional. Default=-1. The number of processors (cores) to limit
                generation to or -1 for default.
        """
        self.call("setgenerate", generate, genproclimit)

    def stop(self):
        """
        Shutdown dcrd.

        Returns:
            str: 'dcrd stopping.'
        """
        return self.call("stop")

    def submitBlock(self, hexblock, options={}):
        """
        Attempts to submit a new serialized, hex-encoded block to the network.

        Args:
            hexblock (str): Serialized, hex-encoded block.
            options: Optional. Default={}. This parameter is currently ignored.

        Returns:
            str: The reason the block was rejected if rejected or None.
        """
        return self.call("submitblock", hexblock, options)

    def ticketFeeInfo(self, blocks=None, windows=None):
        """
        Get various information about ticket fees from the mempool, blocks, and
        difficulty windows (units: DCR/kB).

        Args:
            blocks (int): Optional. Default=None. The number of blocks, starting from the
                chain tip and descending, to return fee information about.
            windows (int): Optional. Default=None. The number of difficulty windows to return
                ticket fee information about.

        Returns:
            dict[string]FeeInfoResult: FeeInfoResults for the keys
                "feeinfomempool", "feeinfoblocks", and "feeinfowindows".
        """
        return {
            k: FeeInfoResult.parse(v)
            for k, v in self.call("ticketfeeinfo", blocks, windows).items()
            if v
        }

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
        return self.call("ticketvwap", start, end)

    def txFeeInfo(self, blocks=None, rangeStart=None, rangeEnd=None):
        """
        Get various information about regular transaction fees from the mempool,
        blocks, and difficulty windows.

        Args:
            blocks (int): Optional. Default=None. The number of blocks to calculate transaction fees
                for, starting from the end of the tip moving backwards.
            rangeStart (int): Optional. Default=None. The start height of the block range to calculate
                transaction fees for.
            rangeEnd (int): Optional. Default=None. The end height of the block range to calculate
                transaction fees for.

        Returns:
            dict[string]FeeInfoResult: FeeInfoResults for the keys
                "feeinfomempool", "feeinfoblocks", and "feeinforange".
        """
        return {
            k: FeeInfoResult.parse(v)
            for k, v in self.call("txfeeinfo", blocks, rangeStart, rangeEnd).items()
            if v
        }

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
            dict[string]VersionResult: dcrd's version info with keys "dcrd" and "dcrdjsonrpcapi".
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
            chainWork (str):  Hex encoded total work done for the chain.
            initialBlockDownload (boolean): Best guess of whether this node is
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


class SearchRawTransactionsResult:
    """searchrawtransactions"""

    def __init__(
        self,
        txid,
        version,
        lockTime,
        expiry,
        vin,
        vout,
        Hex=None,
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
            hex (str): Hex-encoded transaction or None.
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
        self.hex = Hex
        self.blockHash = blockHash
        self.blockHeight = blockHeight
        self.blockIndex = blockIndex
        self.confirmations = confirmations
        self.time = time
        self.blockTime = blockTime

    @staticmethod
    def parse(obj):
        return SearchRawTransactionsResult(
            txid=obj["txid"],
            version=obj["version"],
            lockTime=obj["locktime"],
            expiry=obj["expiry"],
            vin=[Vin.parse(vin) for vin in obj["vin"]],
            vout=[Vout.parse(vout) for vout in obj["vout"]],
            Hex=get("hex", obj),
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
        self, value, addresses=[],
    ):
        """
        Args:
            value (float): previous output value.
            addresses (list(str)): previous output addresses. Maybe empty.
        """
        self.value = value
        self.addresses = addresses

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
        coinbase,
        amountIn,
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
            coinbase (str): The hex-encoded bytes of the signature script
                (coinbase txns only).
            amountIn (int): The amount in for this transaction input, in coins.
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
        self.coinbase = coinbase
        self.amountIn = amountIn
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
            coinbase=obj["coinbase"],
            amountIn=obj["amountin"],
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
        self, asm, Hex,
    ):
        """
        Args:
            asm (str): Disassembly of the script.
            hex (str): Hex-encoded bytes of the script.
        """
        self.asm = asm
        self.hex = Hex

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
            asm=obj["asm"], Hex=obj["hex"],
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
        self, asm, Type, Hex=None, reqSigs=None, addresses=None, commitAmt=None,
    ):
        """
        Args:
            asm (str): Disassembly of the script.
            Type (str): The type of the script (e.g. 'pubkeyhash').
            Hex (str): Hex-encoded bytes of the script or None.
            reqSigs (int): The number of required signatures or None.
            addresses (list(str)): The Decred addresses associated with this
                script or None.
            commitAmt (float): The ticket commitment value if the script is
                for a staking commitment or None.
        """
        self.asm = asm
        self.type = Type
        self.hex = Hex
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
            Hex=get("hex", obj),
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
