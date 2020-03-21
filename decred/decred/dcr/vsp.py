"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details

DcrdataClient.endpointList() for available endpoints.
"""

import time
from urllib.parse import urlsplit, urlunsplit

from decred import DecredError
from decred.dcr import addrlib
from decred.util import encode, tinyhttp
from decred.util.encode import ByteArray, unblobCheck

from . import constants, nets, txscript


# The duration purchase info is good for.
PURCHASE_INFO_LIFE = constants.HOUR

API_URL = "https://api.decred.org/?c=gsd"


def resultIsSuccess(res):
    """
    JSON-decoded stake pool responses have a common base structure that enables
    a universal success check.

    Args:
        res (dict): The freshly-decoded-from-JSON response.

    Returns:
        bool: True if result fields indicate success.
    """
    try:
        return res["status"] == "success"
    except (KeyError, TypeError):
        return False


class PurchaseInfo:
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
            pi (dict): The response from the 'getpurchaseinfo' request.
        """

        return PurchaseInfo(
            addr=pi.get("PoolAddress"),
            fees=pi.get("PoolFees"),
            script=ByteArray(pi["Script"]) if "Script" in pi else None,
            ticketAddr=pi.get("TicketAddress"),
            vBits=pi.get("VoteBits"),
            vBitsVer=pi.get("VoteBitsVersion"),
            stamp=pi.get("unixTimestamp", int(time.time())),
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
        unblobCheck("PurchaseInfo", ver, len(d), {0: 7})

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


class PoolStats:
    """
    PoolStats models the response from the 'stats' endpoint.
    """

    def __init__(self, stats):
        """
        Args:
            stats (dict): The response from the 'stats' request.
        """

        self.allMempoolTix = stats.get("AllMempoolTix")
        self.apiVersionsSupported = stats.get("APIVersionsSupported")
        self.blockHeight = stats.get("BlockHeight")
        self.difficulty = stats.get("Difficulty")
        self.expired = stats.get("Expired")
        self.immature = stats.get("Immature")
        self.live = stats.get("Live")
        self.missed = stats.get("Missed")
        self.ownMempoolTix = stats.get("OwnMempoolTix")
        self.poolSize = stats.get("PoolSize")
        self.proportionLive = stats.get("ProportionLive")
        self.proportionMissed = stats.get("ProportionMissed")
        self.revoked = stats.get("Revoked")
        self.totalSubsidy = stats.get("TotalSubsidy")
        self.voted = stats.get("Voted")
        self.network = stats.get("Network")
        self.poolEmail = stats.get("PoolEmail")
        self.poolFees = stats.get("PoolFees")
        self.poolStatus = stats.get("PoolStatus")
        self.userCount = stats.get("UserCount")
        self.userCountActive = stats.get("UserCountActive")
        self.version = stats.get("Version")


class VotingServiceProvider:
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
        url = urlsplit(url)
        # Remove any path.
        self.url = urlunsplit((url.scheme, url.netloc, "/", "", ""))
        # The network parameters are not JSON-serialized, so must be set during
        # a call to VotingServiceProvider.authorize before using the
        # VotingServiceProvider.
        self.apiKey = apiKey
        self.netParams = nets.parse(netName)
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
            .addData(vsp.netParams.Name.encode("utf-8"))
            .addData(encode.filterNone(pi))
            .b
        )

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        unblobCheck("VotingServiceProvider", ver, len(d), {0: 4})

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
    def providers(netParams):
        """
        A static method to get the current Decred VSP list.

        Args:
            netParams (module): The network parameters.

        Returns:
            list(object): The vsp list.
        """
        vsps = tinyhttp.get(API_URL)
        network = nets.normalizeName(netParams.Name)
        return [vsp for vsp in vsps.values() if vsp["Network"] == network]

    def apiPath(self, command):
        """
        The full URL for the specified command.

        Args:
            command (string): The API endpoint specifier.

        Returns:
            string: The full URL.
        """
        url = urlsplit(self.url)
        return urlunsplit((url.scheme, url.netloc, f"/api/v2/{command}", "", ""))

    def headers(self):
        """
        Make the API request headers.

        Returns:
            dict: The headers as a Python dict.
        """
        return {"Authorization": "Bearer %s" % self.apiKey}

    def validate(self, addr):
        """
        Validate performs some checks that the PurchaseInfo provided by the
        stake pool API is valid for this given voting address. DecredError is
        raised on failure to validate.

        Args:
            addr (string): The base58-encoded pubkey address that the wallet
                uses to vote.
        """
        pi = self.purchaseInfo
        redeemScript = pi.script
        scriptAddr = addrlib.AddressScriptHash.fromScript(redeemScript, self.netParams)
        if scriptAddr.string() != pi.ticketAddress:
            raise DecredError(
                "ticket address mismatch. %s != %s"
                % (pi.ticketAddress, scriptAddr.string())
            )
        # extract addresses
        scriptType, addrs, numSigs = txscript.extractPkScriptAddrs(
            0, redeemScript, self.netParams
        )
        if numSigs != 1:
            raise DecredError("expected 2 required signatures, found 2")
        found = False
        signAddr = addrlib.decodeAddress(addr, self.netParams)
        for addr in addrs:
            if addr.string() == signAddr.string():
                found = True
                break
        if not found:
            raise DecredError("signing pubkey not found in redeem script")

    def authorize(self, address):
        """
        Authorize the stake pool for the provided address and network. DecredError
        is raised on failure to authorize.

        Args:
            address (string): The base58-encoded pubkey address that the wallet
                uses to vote.
        """
        try:
            self.getPurchaseInfo()
            self.validate(address)
        except DecredError as e:
            # code 9 is address not set
            addressNotSet = (
                isinstance(self.err, dict)
                and "code" in self.err
                and self.err["code"] == 9
            )
            if not addressNotSet:
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
                raise DecredError("unexpected response from 'address': %s" % repr(res))

    def getPurchaseInfo(self):
        """
        Get the purchase info from the stake pool API.

        Returns:
            PurchaseInfo: The PurchaseInfo object.
        """
        self.err = None
        res = tinyhttp.get(self.apiPath("getpurchaseinfo"), headers=self.headers())
        if resultIsSuccess(res):
            pi = PurchaseInfo.parse(res["data"])
            # check the script hash
            self.purchaseInfo = pi
            return self.purchaseInfo
        self.err = res
        raise DecredError("unexpected response from 'getpurchaseinfo': %r" % (res,))

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
        raise DecredError("unexpected response from 'stats': %s" % repr(res))

    def setVoteBits(self, voteBits):
        """
        Set the vote preference on the VotingServiceProvider.

        Returns:
            bool: True on success. DecredError raised on error.
        """
        data = {"VoteBits": voteBits}
        res = tinyhttp.post(
            self.apiPath("voting"), data, headers=self.headers(), urlEncode=True
        )
        if resultIsSuccess(res):
            self.purchaseInfo.voteBits = voteBits
            return True
        raise DecredError("unexpected response from 'voting': %s" % repr(res))
