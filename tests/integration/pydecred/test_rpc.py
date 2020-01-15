import pytest
import os
from tinydecred.pydecred import rpc
from tinydecred.util import helpers
from tinydecred.pydecred.wire.msgtx import MsgTx


@pytest.fixture
def config():
    dcrdCfgDir = helpers.appDataDir("dcrd")
    cfgPath = os.path.join(dcrdCfgDir, "dcrd.conf")
    if not os.path.isfile(cfgPath):
        return None
    cfg = helpers.readINI(cfgPath, ["rpcuser", "rpcpass", "rpccert"])
    assert "rpcuser" in cfg
    assert "rpcpass" in cfg
    if "rpccert" not in cfg:
        cfg["rpccert"] = os.path.join(dcrdCfgDir, "rpc.cert")
    if "rpclisten" not in cfg:
        cfg["rpclisten"] = "localhost:9109"
    return cfg


def test_rpc(config):
    if config is None:
        pytest.skip("did not locate a dcrd config file")
    rpcClient = rpc.Client(
        "https://" + config["rpclisten"],
        config["rpcuser"],
        config["rpcpass"],
        config["rpccert"],
    )

    bestBlock = rpcClient.getBestBlock()
    assert isinstance(bestBlock, rpc.GetBestBlockResult)

    blockchainInfo = rpcClient.getBlockchainInfo()
    assert isinstance(blockchainInfo, rpc.GetBlockChainInfoResult)

    getBlockCount = rpcClient.getBlockCount()
    assert isinstance(getBlockCount, int)

    getBlockHash = rpcClient.getBlockHash(0)
    assert (
        getBlockHash
        == "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980"
    )

    getBlockHeader = rpcClient.getBlockHeader(getBlockHash)
    assert isinstance(getBlockHeader, rpc.GetBlockHeaderVerboseResult)

    getBlockHeader = rpcClient.getBlockHeader(getBlockHash, False)
    assert (
        getBlockHeader
        == "0100000000000000000000000000000000000000000000000000000000000000000000000dc101dfc3c6a2eb10ca0c5374e10d28feb53f7eabcc850511ceadb99174aa66000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff011b00c2eb0b000000000000000000000000a0d7b85600000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )

    getBlockSubsidy = rpcClient.getBlockSubsidy(414500, 5)
    assert isinstance(getBlockSubsidy, rpc.GetBlockSubsidyResult)

    getCFilter = rpcClient.getCFilter(
        "000000000000000018744e708a39ad6e0cc22a85d5b902aa2067c9cd0002df85", "extended"
    )
    assert (
        getCFilter
        == "0000000e590860091d85960f114d2e457d101825e82c901465e94aa768191dcae08475a842086ad954d6"
    )

    getCFilterHeader = rpcClient.getCFilterHeader(
        "000000000000000018744e708a39ad6e0cc22a85d5b902aa2067c9cd0002df85", "extended"
    )
    assert (
        getCFilterHeader
        == "412f12ed5bd92df6a8b17cf396697cd44d84ada67f5ca3b1c3f23f3b7619984b"
    )

    getCFilterV2 = rpcClient.getCFilterV2(
        "000000000000000018744e708a39ad6e0cc22a85d5b902aa2067c9cd0002df85"
    )
    assert isinstance(getCFilterV2, rpc.GetCFilterV2Result)

    getChainTips = rpcClient.getChainTips()
    assert isinstance(getChainTips[0], rpc.GetChainTipsResult)

    getCoinSupply = rpcClient.getCoinSupply()
    assert isinstance(getCoinSupply, int)

    getConnectionCount = rpcClient.getConnectionCount()
    assert isinstance(getConnectionCount, int)

    getCurrentNet = rpcClient.getCurrentNet()
    assert isinstance(getCurrentNet, int)

    getDifficulty = rpcClient.getDifficulty()
    assert isinstance(getDifficulty, float)

    getGenerate = rpcClient.getGenerate()
    assert isinstance(getGenerate, bool)

    getHashesPerSec = rpcClient.getHashesPerSec()
    assert isinstance(getHashesPerSec, int)

    getInfo = rpcClient.getInfo()
    assert isinstance(getInfo, rpc.InfoChainResult)

    getMempoolInfo = rpcClient.getMempoolInfo()
    assert isinstance(getMempoolInfo, rpc.GetMempoolInfoResult)

    getMiningInfo = rpcClient.getMiningInfo()
    assert isinstance(getMiningInfo, rpc.GetMiningInfoResult)

    getNetTotals = rpcClient.getNetTotals()
    assert isinstance(getNetTotals, rpc.GetNetTotalsResult)

    getNetworkHashPS = rpcClient.getNetworkHashPS()
    assert isinstance(getNetworkHashPS, int)

    getNetworkInfo = rpcClient.getNetworkInfo()
    assert isinstance(getNetworkInfo, rpc.GetNetworkInfoResult)

    getPeerInfo = rpcClient.getPeerInfo()
    assert isinstance(getPeerInfo[0], rpc.GetPeerInfoResult)

    getRawMempool = rpcClient.getRawMempool()
    assert isinstance(getRawMempool, list)
    key = getRawMempool[0]

    getRawMempool = rpcClient.getRawMempool(True)
    assert isinstance(getRawMempool[key], rpc.GetRawMempoolVerboseResult)

    getHeaders = rpcClient.getHeaders(
        ["00000000000000000224f75f39ae5f464beaf049b40f49baf3fdf07c28bfe53c"],
        "000000000000000008a0ec8c8d1c700391eefb5dd5a553a14d645bbc25c8a880",
    )
    assert (
        "07000000efbdffeb392b83bc7704757470a218afafa7b1431576ca090000000000000000bdef083cc385b81ace60798d6fb6a6aa1888028eff67a2363338077fb4a070c4da514989c0e4d3305307196cd7e08e9400698718ad20ab7e95051e371ee5d55a0100b292099fea9c05000200df9e00003f042118f2fc9460030000006452060088110000ecfe1b5e26ed6e2ec58d670100000000a10030b0000000000000000000000000000000000000000007000000"
        in getHeaders
    )

    # This test will fail if --addrindex is not enabled in dcrd.
    getRawTransaction = rpcClient.getRawTransaction(
        "d54d90bcec4146e9ae8c2ec860364f7023f33cad02b3c2bb4bdbb36689e68614"
    )
    assert isinstance(getRawTransaction, MsgTx)

    getRawTransaction = rpcClient.getRawTransaction(
        "d54d90bcec4146e9ae8c2ec860364f7023f33cad02b3c2bb4bdbb36689e68614", 1
    )
    assert isinstance(getRawTransaction, rpc.RawTransactionsResult)

    getStakeDifficulty = rpcClient.getStakeDifficulty()
    assert isinstance(getStakeDifficulty, rpc.GetStakeDifficultyResult)

    getStakeVersionInfo = rpcClient.getStakeVersionInfo()
    assert isinstance(getStakeVersionInfo, rpc.GetStakeVersionInfoResult)

    getStakeVersions = rpcClient.getStakeVersions(
        "000000000000000019ba461e9d123d84d6babc1f8a0e050f7788cbbdd522c417", 3
    )
    assert isinstance(getStakeVersions[0], rpc.GetStakeVersionsResult)

    getTicketPoolValue = rpcClient.getTicketPoolValue()
    assert isinstance(getTicketPoolValue, float)

    getTxOut = rpcClient.getTxOut(
        "28289634ba3c329a92ddb2d8f726429fb096f9b3d5b7104e17f25f2e7dd2709d", 0
    )
    assert isinstance(getTxOut, rpc.GetTxOutResult)

    getVoteInfo = rpcClient.getVoteInfo(7)
    assert isinstance(getVoteInfo, rpc.GetVoteInfoResult)

    # getWork will fail if --mininaddr is not set when starting dcrd
    # getWork = rpcClient.getWork()
    # assert isinstance(getWork, rpc.GetWorkResult)

    dcrdHelp = rpcClient.help()
    assert isinstance(dcrdHelp, str)

    dcrdHelp = rpcClient.help("getinfo")
    assert isinstance(dcrdHelp, str)

    liveTickets = rpcClient.liveTickets()
    assert isinstance(liveTickets, list)

    missedTickets = rpcClient.missedTickets()
    assert isinstance(missedTickets, list)

    rpcClient.ping()

    searchRawTransactions = rpcClient.searchRawTransactions(
        "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx"
    )
    assert isinstance(searchRawTransactions[0], rpc.RawTransactionsResult)

    searchRawTransactions = rpcClient.searchRawTransactions(
        "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx", 0,
    )
    assert isinstance(searchRawTransactions[0], str)

    ticketFeeInfo = rpcClient.ticketFeeInfo()
    assert isinstance(ticketFeeInfo, rpc.TicketFeeInfoResult)

    ticketFeeInfo = rpcClient.ticketFeeInfo(5, 5)
    assert isinstance(ticketFeeInfo, rpc.TicketFeeInfoResult)

    ticketsForAddress = rpcClient.ticketsForAddress(
        "DcaephHCqjdfb3gPz778DJZWvwmUUs3ssGk"
    )
    assert (
        "d54d90bcec4146e9ae8c2ec860364f7023f33cad02b3c2bb4bdbb36689e68614"
        in ticketsForAddress
    )

    ticketVWAP = rpcClient.ticketVWAP()
    assert isinstance(ticketVWAP, float)

    ticketVWAP = rpcClient.ticketVWAP(414500)
    assert isinstance(ticketVWAP, float)

    ticketVWAP = rpcClient.ticketVWAP(414500, 414510)
    assert isinstance(ticketVWAP, float)

    txFeeInfo = rpcClient.txFeeInfo()
    assert isinstance(txFeeInfo, rpc.TxFeeInfoResult)

    txFeeInfo = rpcClient.txFeeInfo(5)
    assert isinstance(txFeeInfo, rpc.TxFeeInfoResult)
    tip = txFeeInfo.feeInfoBlocks[0].height

    txFeeInfo = rpcClient.txFeeInfo(5, tip - 5, tip)
    assert isinstance(txFeeInfo, rpc.TxFeeInfoResult)

    validateAddress = rpcClient.validateAddress("DsUxwT6Kbiur6Nps9q3uGEpJCvrhcxX2nii")
    assert isinstance(validateAddress, rpc.ValidateAddressChainResult)
    assert validateAddress.isValid

    # Address for wrong network.
    validateAddress = rpcClient.validateAddress("Tsf5Qvq2m7X5KzTZDdSGfa6WrMtikYVRkaL")
    assert isinstance(validateAddress, rpc.ValidateAddressChainResult)
    assert not validateAddress.isValid

    # Address is bogus.
    validateAddress = rpcClient.validateAddress("asdf")
    assert isinstance(validateAddress, rpc.ValidateAddressChainResult)
    assert not validateAddress.isValid

    verifyChain = rpcClient.verifyChain()
    assert verifyChain

    verifyMessage = rpcClient.verifyMessage(
        "DsUxwT6Kbiur6Nps9q3uGEpJCvrhcxX2nii",
        "H166ndZLNEpIXrcEm4V9lf+AizRp/ejCAhs21J/ht87/RK0QFnOscCbJixKok3oHjpOS0jAkJ4jFktqMXD59LU8=",
        "this decred is tiny",
    )
    assert verifyMessage

    # Signature is bogus.
    verifyMessage = rpcClient.verifyMessage(
        "DsUxwT6Kbiur6Nps9q3uGEpJCvrhcxX2nii", "asdf", "this decred is tiny",
    )
    assert not verifyMessage

    version = rpcClient.version()
    assert isinstance(version["dcrd"], rpc.VersionResult)
    assert isinstance(version["dcrdjsonrpcapi"], rpc.VersionResult)
