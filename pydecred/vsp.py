"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

DcrdataClient.endpointList() for available enpoints.
"""
import time
from tinydecred.util import tinyhttp, encode
from tinydecred.pydecred import txscript, constants, nets
from tinydecred.crypto import crypto
from tinydecred.util.encode import ByteArray

# The duration purchase info is good for.
PURCHASE_INFO_LIFE = constants.HOUR


def resultIsSuccess(res):
    """
    JSON-decoded stake pool responses have a common base structure that enables
    a universal success check.

    Args:
        res (object): The freshly-decoded-from-JSON response.

    Returns:
        bool: True if result fields indicate success.
    """
    return (
        res
        and isinstance(res, object)
        and "status" in res
        and res["status"] == "success"
    )


class PurchaseInfo(object):
    """
    The PurchaseInfo models the response from the 'getpurchaseinfo' endpoint.
    This information is required for validating the pool and creating tickets.
    """

    def __init__(self, addr, fees, script, ticketAddr, vBits, vBitsVer, stamp):
        """
        Constructor for a PurchaseInfo.

        Args;
            addr (str): The pool address.
            fees (float): The pool ticket fee rate, as percent.
            script (ByteArray): The P2SH ticket script.
            ticketAddr (str): The P2SH address derived from the script.
            vBits (int): Current account vote bits.
            vBitsVer: (int): The vote bits version.
            stamp (int): Unix timestamp that the purchase info was last updated.
        """
        self.poolAddress = addr
        self.poolFees = fees
        self.script = script
        self.ticketAddress = ticketAddr
        self.voteBits = vBits
        self.voteBitsVersion = vBitsVer
        self.unixTimestamp = stamp

    @staticmethod
    def parse(pi):
        """
        Args:
            pi (object): The response from the 'getpurchaseinfo' request.
        """
        get = lambda k, default=None: pi[k] if k in pi else default
        return PurchaseInfo(
            addr=get("PoolAddress"),
            fees=get("PoolFees"),
            script=ByteArray(get("Script")),
            ticketAddr=get("TicketAddress"),
            vBits=get("VoteBits"),
            vBitsVer=get("VoteBitsVersion"),
            stamp=get("unixTimestamp", default=int(time.time())),
        )

    @staticmethod
    def blob(pi):
        """Satisfies the encode.Blobber API"""
        return (
            encode.BuildyBytes(0)
            .addData(pi.poolAddress.encode("utf-8"))
            .addData(encode.floatToBytes(pi.poolFees))
            .addData(pi.script)
            .addData(pi.ticketAddress.encode("utf-8"))
            .addData(pi.voteBits)
            .addData(pi.voteBitsVersion)
            .addData(pi.unixTimestamp)
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("invalid PurchaseInfo version %d" % ver)
        if len(d) != 7:
            raise AssertionError(
                "wrong number of pushes for PurchaseInfo. expected 7, got %d" % len(d)
            )

        iFunc = encode.intFromBytes

        return PurchaseInfo(
            addr=d[0].decode("utf-8"),
            fees=encode.floatFromBytes(d[1]),
            script=ByteArray(d[2]),
            ticketAddr=d[3].decode("utf-8"),
            vBits=iFunc(d[4]),
            vBitsVer=iFunc(d[5]),
            stamp=iFunc(d[6]),
        )


class PoolStats(object):
    """
    PoolStats models the response from the 'stats' endpoint.
    """

    def __init__(self, stats):
        """
        Args:
            stats (object): The response from the 'stats' request.
        """
        get = lambda k, default=None: stats[k] if k in stats else default
        self.allMempoolTix = get("AllMempoolTix")
        self.apiVersionsSupported = get("APIVersionsSupported")
        self.blockHeight = get("BlockHeight")
        self.difficulty = get("Difficulty")
        self.expired = get("Expired")
        self.immature = get("Immature")
        self.live = get("Live")
        self.missed = get("Missed")
        self.ownMempoolTix = get("OwnMempoolTix")
        self.poolSize = get("PoolSize")
        self.proportionLive = get("ProportionLive")
        self.proportionMissed = get("ProportionMissed")
        self.revoked = get("Revoked")
        self.totalSubsidy = get("TotalSubsidy")
        self.voted = get("Voted")
        self.network = get("Network")
        self.poolEmail = get("PoolEmail")
        self.poolFees = get("PoolFees")
        self.poolStatus = get("PoolStatus")
        self.userCount = get("UserCount")
        self.userCountActive = get("UserCountActive")
        self.version = get("Version")


class VotingServiceProvider(object):
    """
    A VotingServiceProvider is a voting service provider, uniquely defined by
    its URL. The VotingServiceProvider class has methods for interacting with
    the VSP API.
    """

    def __init__(self, url, apiKey, netName, purchaseInfo=None):
        """
        Args:
            url (string): The stake pool URL.
            apiKey (string): The API key assigned to the VSP account during
                registration.
            netName (string): The network for this vsp account.
            purchaseInfo (PurchaseInfo): optional. The current purchaseInfo for
                this vsp.
        """
        self.url = url
        # The network parameters are not JSON-serialized, so must be set during
        # a call to VotingServiceProvider.authorize before using the
        # VotingServiceProvider.
        self.apiKey = apiKey
        self.net = nets.parse(netName)
        self.purchaseInfo = purchaseInfo
        self.stats = None
        self.err = None

    @staticmethod
    def blob(vsp):
        """Satisfies the encode.Blobber API"""
        pi = PurchaseInfo.blob(vsp.purchaseInfo) if vsp.purchaseInfo else None
        return (
            encode.BuildyBytes(0)
            .addData(vsp.url.encode("utf-8"))
            .addData(vsp.apiKey.encode("utf-8"))
            .addData(vsp.net.Name.encode("utf-8"))
            .addData(encode.filterNone(pi))
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        if ver != 0:
            raise AssertionError("invalid version for VotingServiceProvider %d" % ver)
        if len(d) != 4:
            raise AssertionError(
                "wrong number of pushes for VotingServiceProvider. wanted 4, got %d"
                % len(d)
            )

        piB = encode.extractNone(d[3])
        pi = PurchaseInfo.unblob(piB) if piB else None

        return VotingServiceProvider(
            url=d[0].decode("utf-8"),
            apiKey=d[1].decode("utf-8"),
            netName=d[2].decode("utf-8"),
            purchaseInfo=pi,
        )

    def serialize(self):
        """
        Serialize the VotingServiceProvider.

        Returns:
            ByteArray: The serialized VotingServiceProvider.
        """
        return ByteArray(VotingServiceProvider.blob(self))

    @staticmethod
    def providers(net):
        """
        A static method to get the current Decred VSP list.

        Args:
            net (string): The network name.

        Returns:
            list(object): The vsp list.
        """
        vsps = tinyhttp.get("https://api.decred.org/?c=gsd")
        network = "testnet" if net.Name == "testnet3" else net.Name
        return [vsp for vsp in vsps.values() if vsp["Network"] == network]

    def apiPath(self, command):
        """
        The full URL for the specified command.

        Args:
            command (string): The API endpoint specifier.

        Returns:
            string: The full URL.
        """
        return "%s/api/v2/%s" % (self.url, command)

    def headers(self):
        """
        Make the API request headers.

        Returns:
            object: The headers as a Python object.
        """
        return {"Authorization": "Bearer %s" % self.apiKey}

    def validate(self, addr):
        """
        Validate performs some checks that the PurchaseInfo provided by the
        stake pool API is valid for this given voting address. Exception is
        raised on failure to validate.

        Args:
            addr (string): The base58-encoded pubkey address that the wallet
                uses to vote.
        """
        pi = self.purchaseInfo
        redeemScript = pi.script
        scriptAddr = crypto.newAddressScriptHash(redeemScript, self.net)
        if scriptAddr.string() != pi.ticketAddress:
            raise Exception(
                "ticket address mismatch. %s != %s"
                % (pi.ticketAddress, scriptAddr.string())
            )
        # extract addresses
        scriptType, addrs, numSigs = txscript.extractPkScriptAddrs(
            0, redeemScript, self.net
        )
        if numSigs != 1:
            raise Exception("expected 2 required signatures, found 2")
        found = False
        signAddr = txscript.decodeAddress(addr, self.net)
        for addr in addrs:
            if addr.string() == signAddr.string():
                found = True
                break
        if not found:
            raise Exception("signing pubkey not found in redeem script")

    def authorize(self, address):
        """
        Authorize the stake pool for the provided address and network. Exception
        is raised on failure to authorize.

        Args:
            address (string): The base58-encoded pubkey address that the wallet
                uses to vote.
        """
        # An error is returned if the address is already set
        # {'status': 'error', 'code': 6,
        #     'message': 'address error - address already submitted'}
        # First try to get the purchase info directly.
        try:
            self.getPurchaseInfo()
            self.validate(address)
        except Exception as e:
            # code 9 is address not set
            alreadyRegistered = (
                isinstance(self.err, dict)
                and "code" in self.err
                and self.err["code"] == 9
            )
            if not alreadyRegistered:
                raise e
            # address is not set
            data = {"UserPubKeyAddr": address}
            res = tinyhttp.post(
                self.apiPath("address"), data, headers=self.headers(), urlEncode=True
            )
            if resultIsSuccess(res):
                self.getPurchaseInfo()
                self.validate(address)
            else:
                raise Exception("unexpected response from 'address': %s" % repr(res))

    def getPurchaseInfo(self):
        """
        Get the purchase info from the stake pool API.

        Returns:
            PurchaseInfo: The PurchaseInfo object.
        """
        # An error is returned if the address isn't yet set
        # {'status': 'error', 'code': 9,
        #  'message': 'purchaseinfo error - no address submitted',
        # 'data': None}
        self.err = None
        res = tinyhttp.get(self.apiPath("getpurchaseinfo"), headers=self.headers())
        if resultIsSuccess(res):
            pi = PurchaseInfo.parse(res["data"])
            # check the script hash
            self.purchaseInfo = pi
            return self.purchaseInfo
        self.err = res
        raise Exception("unexpected response from 'getpurchaseinfo': %r" % (res,))

    def updatePurchaseInfo(self):
        """
        Update purchase info if older than PURCHASE_INFO_LIFE.
        """
        if time.time() - self.purchaseInfo.unixTimestamp > PURCHASE_INFO_LIFE:
            self.getPurchaseInfo()

    def getStats(self):
        """
        Get the stats from the stake pool API.

        Returns:
            Poolstats: The PoolStats object.
        """
        res = tinyhttp.get(self.apiPath("stats"), headers=self.headers())
        if resultIsSuccess(res):
            self.stats = PoolStats(res["data"])
            return self.stats
        raise Exception("unexpected response from 'stats': %s" % repr(res))

    def setVoteBits(self, voteBits):
        """
        Set the vote preference on the VotingServiceProvider.

        Returns:
            bool: True on success. Exception raised on error.
        """
        data = {"VoteBits": voteBits}
        res = tinyhttp.post(
            self.apiPath("voting"), data, headers=self.headers(), urlEncode=True
        )
        if resultIsSuccess(res):
            self.purchaseInfo.voteBits = voteBits
            return True
        raise Exception("unexpected response from 'voting': %s" % repr(res))
