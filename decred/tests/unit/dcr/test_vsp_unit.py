"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import time

import pytest

from decred import DecredError
from decred.dcr import vsp
from decred.dcr.nets import mainnet
from decred.util import encode


def test_result_is_success():
    class test:
        def __init__(
            self, res, isSuccess,
        ):
            self.res = res
            self.isSuccess = isSuccess

    tests = [
        test({"status": "success"}, True,),
        test({"status": "fail"}, False,),
        test({}, False,),
        test("abcd", False,),
    ]
    for test in tests:
        assert vsp.resultIsSuccess(test.res) is test.isSuccess


purchaseInfo = {
    "PoolAddress": "TsbyH2p611jSWnvUAq3erSsRYnCxBg3nT2S",
    "PoolFees": 0.5,
    "Script": "512103af3c24d005ca8b755e7167617f3a5b4c60a65f8318a7fcd1b0cacb1abd2a97fc21027b81bc16954e28adb832248140eb58bedb6078ae5f4dabf21fde5a8ab7135cb652ae",
    "TicketAddress": "Tcbvn2hiEAXBDwUPDLDG2SxF9iANMKhdVev",
    "VoteBits": 5,
    "VoteBitsVersion": 0,
}


def test_purchase_info_parse():

    now = int(time.time())
    pi = vsp.PurchaseInfo.parse(purchaseInfo)

    assert pi.poolAddress == "TsbyH2p611jSWnvUAq3erSsRYnCxBg3nT2S"
    assert pi.poolFees == 0.5
    assert (
        pi.script
        == "512103af3c24d005ca8b755e7167617f3a5b4c60a65f8318a7fcd1b0cacb1abd2a97fc21027b81bc16954e28adb832248140eb58bedb6078ae5f4dabf21fde5a8ab7135cb652ae"
    )
    assert pi.ticketAddress == "Tcbvn2hiEAXBDwUPDLDG2SxF9iANMKhdVev"
    assert pi.voteBits == 5
    assert pi.voteBitsVersion == 0
    assert isinstance(pi.unixTimestamp, int) and pi.unixTimestamp >= now


def test_purchase_info_blobbing():

    pi = vsp.PurchaseInfo.parse(purchaseInfo)
    stamp = pi.unixTimestamp
    b = vsp.PurchaseInfo.blob(pi)
    assert isinstance(b, bytearray)

    rePi = vsp.PurchaseInfo.unblob(b)
    assert rePi.poolAddress == "TsbyH2p611jSWnvUAq3erSsRYnCxBg3nT2S"
    assert rePi.poolFees == 0.5
    assert (
        rePi.script
        == "512103af3c24d005ca8b755e7167617f3a5b4c60a65f8318a7fcd1b0cacb1abd2a97fc21027b81bc16954e28adb832248140eb58bedb6078ae5f4dabf21fde5a8ab7135cb652ae"
    )
    assert rePi.ticketAddress == "Tcbvn2hiEAXBDwUPDLDG2SxF9iANMKhdVev"
    assert rePi.voteBits == 5
    assert rePi.voteBitsVersion == 0
    assert rePi.unixTimestamp == stamp

    # bad version
    bCopy = encode.ByteArray(b, copy=True)
    bCopy[0] = 255
    with pytest.raises(AssertionError):
        vsp.PurchaseInfo.unblob(bCopy.bytes())

    # too long
    bCopy = encode.ByteArray(b, copy=True)
    bCopy += b"\x00"
    with pytest.raises(AssertionError):
        vsp.PurchaseInfo.unblob(bCopy.bytes())


poolStats = {
    "AllMempoolTix": 12,
    "APIVersionsSupported": [1, 2],
    "BlockHeight": 368781,
    "Difficulty": 88.50820708,
    "Expired": 3,
    "Immature": 0,
    "Live": 28,
    "Missed": 349,
    "OwnMempoolTix": 0,
    "PoolSize": 5759,
    "ProportionLive": 0.004861955200555652,
    "ProportionMissed": 0.3216589861751152,
    "Revoked": 349,
    "TotalSubsidy": 293.10719669,
    "Voted": 736,
    "Network": "testnet3",
    "PoolEmail": "joe@dcrstakedinner.com",
    "PoolFees": 0.5,
    "PoolStatus": "Open",
    "UserCount": 44,
    "UserCountActive": 34,
    "Version": "1.6.0-pre",
}


def test_pool_stats():

    ps = vsp.PoolStats(poolStats)

    assert ps.allMempoolTix == 12
    assert ps.apiVersionsSupported == [1, 2]
    assert ps.blockHeight == 368781
    assert ps.difficulty == 88.50820708
    assert ps.expired == 3
    assert ps.immature == 0
    assert ps.live == 28
    assert ps.missed == 349
    assert ps.ownMempoolTix == 0
    assert ps.poolSize == 5759
    assert ps.proportionLive == 0.004861955200555652
    assert ps.proportionMissed == 0.3216589861751152
    assert ps.revoked == 349
    assert ps.totalSubsidy == 293.10719669
    assert ps.voted == 736
    assert ps.network == "testnet3"
    assert ps.poolEmail == "joe@dcrstakedinner.com"
    assert ps.poolFees == 0.5
    assert ps.poolStatus == "Open"
    assert ps.userCount == 44
    assert ps.userCountActive == 34
    assert ps.version == "1.6.0-pre"


votingServiceProvider = {
    "url": "https://www.dcrstakedinner.com",
    "apiKey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1Nzc0MzM0NDIsImlzcyI6Imh0dHBzOi8vd3d3LmRjcnN0YWtlZGlubmVyLmNvbSIsImxvZ2dlZEluQXMiOjQ2fQ.PEb000_TjQuBYxjRdh-VOaXMdV2GUw3_ZyIyp_tfpFE",
    "netName": "testnet3",
    "purchaseInfo": vsp.PurchaseInfo.parse(purchaseInfo),
}


def test_vsp_init():

    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    assert pool.url == "https://www.dcrstakedinner.com"
    assert pool.apiKey == votingServiceProvider["apiKey"]
    assert pool.net.Name == "testnet3"
    assert pool.purchaseInfo.ticketAddress == "Tcbvn2hiEAXBDwUPDLDG2SxF9iANMKhdVev"


def test_vsp_blobbing():

    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    b = vsp.VotingServiceProvider.blob(pool)
    assert isinstance(b, bytearray)

    rePool = vsp.VotingServiceProvider.unblob(b)
    assert rePool.url == "https://www.dcrstakedinner.com"
    assert rePool.apiKey == votingServiceProvider["apiKey"]
    assert rePool.net.Name == "testnet3"
    assert rePool.purchaseInfo.ticketAddress == "Tcbvn2hiEAXBDwUPDLDG2SxF9iANMKhdVev"

    # bad version
    bCopy = encode.ByteArray(b, copy=True)
    bCopy[0] = 255
    with pytest.raises(AssertionError):
        vsp.VotingServiceProvider.unblob(bCopy.bytes())

    # too long
    bCopy = encode.ByteArray(b, copy=True)
    bCopy += b"\x00"
    with pytest.raises(AssertionError):
        vsp.VotingServiceProvider.unblob(bCopy.bytes())


def test_vsp_serialize():
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    b = vsp.VotingServiceProvider.blob(pool)
    assert pool.serialize() == encode.ByteArray(b)


vspProviders = {
    "Staked": {
        "APIEnabled": True,
        "APIVersionsSupported": [1, 2],
        "Network": "mainnet",
        "URL": "https://decred.staked.us",
        "Launched": 1543433400,
        "LastUpdated": 1582020568,
        "Immature": 0,
        "Live": 141,
        "Voted": 2730,
        "Missed": 10,
        "PoolFees": 5,
        "ProportionLive": 0.0034847511245118877,
        "ProportionMissed": 0.0036496350364963502,
        "UserCount": 229,
        "UserCountActive": 106,
        "Version": "1.4.0-pre+dev",
    },
    "Golf": {
        "APIEnabled": True,
        "APIVersionsSupported": [1, 2],
        "Network": "mainnet",
        "URL": "https://stakepool.dcrstats.com",
        "Launched": 1464167340,
        "LastUpdated": 1582020568,
        "Immature": 21,
        "Live": 768,
        "Voted": 148202,
        "Missed": 154,
        "PoolFees": 5,
        "ProportionLive": 0.01898077208244773,
        "ProportionMissed": 0,
        "UserCount": 6005,
        "UserCountActive": 2751,
        "Version": "1.5.0-pre",
    },
    "Hotel": {
        "APIEnabled": True,
        "APIVersionsSupported": [1, 2],
        "Network": "mainnet",
        "URL": "https://stake.decredbrasil.com",
        "Launched": 1464463860,
        "LastUpdated": 1582020568,
        "Immature": 41,
        "Live": 607,
        "Voted": 48135,
        "Missed": 49,
        "PoolFees": 5,
        "ProportionLive": 0.015002842383647644,
        "ProportionMissed": 0.0010169350821849577,
        "UserCount": 1607,
        "UserCountActive": 968,
        "Version": "1.5.0",
    },
    "November": {
        "APIEnabled": True,
        "APIVersionsSupported": [1, 2],
        "Network": "mainnet",
        "URL": "https://decred.raqamiya.net",
        "Launched": 1513878600,
        "LastUpdated": 1582020568,
        "Immature": 5,
        "Live": 334,
        "Voted": 15720,
        "Missed": 50,
        "PoolFees": 1,
        "ProportionLive": 0.008255270767937913,
        "ProportionMissed": 0.0031705770450221942,
        "UserCount": 261,
        "UserCountActive": 114,
        "Version": "1.5.0-pre",
    },
    "Ray": {
        "APIEnabled": True,
        "APIVersionsSupported": [1, 2],
        "Network": "mainnet",
        "URL": "https://dcrpos.idcray.com",
        "Launched": 1518446640,
        "LastUpdated": 1582020569,
        "Immature": 50,
        "Live": 1108,
        "Voted": 36974,
        "Missed": 298,
        "PoolFees": 2,
        "ProportionLive": 0.027385748535554512,
        "ProportionMissed": 0.007995277956643057,
        "UserCount": 137,
        "UserCountActive": 70,
        "Version": "1.4.0-pre+dev",
    },
}


def test_vsp_providers(http_get_post):
    http_get_post("https://api.decred.org/?c=gsd", vspProviders)
    providers = vsp.VotingServiceProvider.providers(mainnet)
    assert len(providers) == 5


def test_vsp_api_path():
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    path = pool.apiPath("stakeinfo")
    assert path == "https://www.dcrstakedinner.com/api/v2/stakeinfo"


def test_vsp_headers():
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    headers = pool.headers()
    assert headers == {"Authorization": "Bearer " + votingServiceProvider["apiKey"]}


def test_vsp_validate():
    pool = vsp.VotingServiceProvider(**votingServiceProvider)

    # correct address
    addr = "TkKmVKG7u7PwhQaYr7wgMqBwHneJ2cN4e5YpMVUsWSopx81NFXEzK"
    pool.validate(addr)

    # valid but wrong address
    addr = "TkQ4jEVTpGn1LZBPrAoUJ15fDGGHubzd1DDkMSc4hxtHXpHjW1BJ8"
    with pytest.raises(DecredError):
        pool.validate(addr)

    # invalid address
    addr = "ASDF"
    with pytest.raises(DecredError):
        pool.validate(addr)

    # no address
    addr = ""
    with pytest.raises(DecredError):
        pool.validate(addr)


def test_vsp_authorize(http_get_post):
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    success = {"status": "success", "data": purchaseInfo}
    addressNotSet = {
        "status": "error",
        "code": 9,
        "message": "no address submitted",
    }

    # ok
    addr = "TkKmVKG7u7PwhQaYr7wgMqBwHneJ2cN4e5YpMVUsWSopx81NFXEzK"
    http_get_post(pool.apiPath("getpurchaseinfo"), success)
    pool.authorize(addr)

    # address not submitted
    addr = "TkKmVKG7u7PwhQaYr7wgMqBwHneJ2cN4e5YpMVUsWSopx81NFXEzK"
    http_get_post(pool.apiPath("getpurchaseinfo"), addressNotSet)
    http_get_post(pool.apiPath("getpurchaseinfo"), success)
    http_get_post((pool.apiPath("address"), repr({"UserPubKeyAddr": addr})), success)
    pool.authorize(addr)

    # other error
    systemErr = {"status": "error", "code": 14, "message": "system error"}
    addr = "TkKmVKG7u7PwhQaYr7wgMqBwHneJ2cN4e5YpMVUsWSopx81NFXEzK"
    http_get_post(pool.apiPath("getpurchaseinfo"), systemErr)
    with pytest.raises(DecredError):
        pool.authorize(addr)

    # wrong address
    addr = "TkQ4jEVTpGn1LZBPrAoUJ15fDGGHubzd1DDkMSc4hxtHXpHjW1BJ8"
    http_get_post(pool.apiPath("getpurchaseinfo"), systemErr)
    with pytest.raises(DecredError):
        pool.authorize(addr)


def test_vsp_get_purchase_info(http_get_post):
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    success = {"status": "success", "data": purchaseInfo}

    addressNotSet = {
        "status": "error",
        "code": 9,
        "message": "no address submitted",
    }

    # ok
    http_get_post(pool.apiPath("getpurchaseinfo"), success)
    pool.getPurchaseInfo()
    assert not pool.err

    # error
    http_get_post(pool.apiPath("getpurchaseinfo"), addressNotSet)
    with pytest.raises(DecredError):
        pool.getPurchaseInfo()
    assert pool.err


def test_vsp_update_purchase_info(http_get_post):
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    success = {"status": "success", "data": purchaseInfo}

    # updated
    pool.purchaseInfo.unixTimestamp = 0
    http_get_post(pool.apiPath("getpurchaseinfo"), success)
    pool.updatePurchaseInfo()
    assert pool.purchaseInfo.unixTimestamp != 0

    # not updated
    # within the update threshhold
    before = int(time.time() - vsp.PURCHASE_INFO_LIFE / 2)
    pool.purchaseInfo.unixTimestamp = before
    pool.updatePurchaseInfo()
    assert pool.purchaseInfo.unixTimestamp == before


def test_vsp_get_stats(http_get_post):
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    success = {"status": "success", "data": poolStats}

    # ok
    http_get_post(pool.apiPath("stats"), success)
    pool.getStats()

    # pool error
    systemErr = {"status": "error", "code": 14, "message": "system error"}
    http_get_post(pool.apiPath("stats"), systemErr)
    with pytest.raises(DecredError):
        pool.getStats()


def test_vsp_set_vote_bits(http_get_post):
    pool = vsp.VotingServiceProvider(**votingServiceProvider)
    success = {"status": "success", "data": "ok"}

    # votebits are 5
    assert pool.purchaseInfo.voteBits == 5

    # ok
    http_get_post((pool.apiPath("voting"), repr({"VoteBits": 7})), success)
    pool.setVoteBits(7)
    # set to 7
    assert pool.purchaseInfo.voteBits == 7

    # pool error
    systemErr = {"status": "error", "code": 14, "message": "system error"}
    http_get_post((pool.apiPath("voting"), repr({"VoteBits": 3})), systemErr)
    with pytest.raises(DecredError):
        pool.setVoteBits(3)
    # no change
    assert pool.purchaseInfo.voteBits == 7
