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
