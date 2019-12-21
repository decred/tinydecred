import base64
import ssl
from tinydecred.util import tinyhttp
from tinydecred.util.encode import ByteArray


class Client(object):
    """
    The Client communicates with the blockchain RPC API.
    """

    def __init__(self, host, user, pw, cert=None):
        """
        Args:
            host (string): The RPC address
            user (string): The rpcuser set in the dcrd configuration
            pw   (string): The rpcpass set in the dcrd configuration
            cert (string): optional. The location of the server's TLS
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

    def validateAddress(self, addr):
        """
        Validate an address.

        Args:
            addr (string): The address to validate.

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
            addr (string): The address used to sign.
            sig (string): The signed message.
            message (string): The message.

        Returns:
            bool: Whether the message could be verified.
        """
        return self.call("verifymessage", addr, sig, message)

    def version(self):
        """
        Get the dcrd and dcrdjsonrpcapi version info.

        Returns:
            dict[string]VersionResult: dcrd's version info with keys "dcrd" and "dcrdjsonrpcapi" .
        """
        return {k: VersionResult.parse(v) for k, v in self.call("version").items()}


def get(k, obj):
    """
    Helper method to check for nil keys and set those values to None.
    Args:
        k (string): dict key
        obj (dict): the dict to search

    Returns:
        object: the thing found at k or None.
    """
    return obj[k] if k in obj else None


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
                "failed"
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


class ValidateAddressChainResult:
    """validateaddress"""

    def __init__(
        self, isValid, address,
    ):
        """
        Args:
            isValid (bool): Whether the address is valid.
            address (string): The address or None if not valid.
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
            versionString (string): The semver version as a string.
            major (int): The semver major.
            minor (int): The semver minor.
            patch (int): The semver patch.
            prerelease (string): Prerelease status.
            buildMetadata (string): The go version used to build the dcrd binary.
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
