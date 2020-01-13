import pytest
import os
from tinydecred.pydecred import rpc
from tinydecred.util import helpers


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
    assert (
        getRawTransaction
        == "01000000025a695e6b701a46d18a9e4dd6368d940826b5a35db1365c6a7a0363d6159436c00000000000ffffffff5a695e6b701a46d18a9e4dd6368d940826b5a35db1365c6a7a0363d6159436c00100000000ffffffff05e465148403000000000018baa914230855dc6ce835c75ce4cef02290ef5662a3b2f18700000000000000000000206a1e42facce70af7031ca5b512dada6a6d2b4ed78350676d0e00000000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000000000000000206a1efa92f61fe0870f733e9b167e55affa8c26614b2ba90d0684030000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac000000002031060002676d0e0000000000f7300600040000006b483045022100cb729097ec5ec1597d53860f07cf1b048e7f930a8a6f1557d6d1bd50d85fae1e02207448d148f481383b1fcebb2f1ca67eec4349e5328485a4a029a31da1d39de62e012102a7ad708544f66a9061208c6d5246f6cd3196383d8fb6f60a3f4ef7fd3e0ff15da90d068403000000f7300600040000006a47304402204ad3e1f247ff30c344b3974fb71dc9af48190c7aa9fc835d7b3f3dff6cc74216022014e491971d2097c610cc1a1e884795e9d477976e60dd54a614a469dc34c5f194012102a7ad708544f66a9061208c6d5246f6cd3196383d8fb6f60a3f4ef7fd3e0ff15d"
    )

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

    getWork = rpcClient.getWork()
    assert isinstance(getWork, rpc.GetWorkResult)

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
    assert isinstance(ticketFeeInfo["feeinfomempool"], rpc.FeeInfoResult)

    ticketsForAddress = rpcClient.ticketsForAddress(
        "DcaephHCqjdfb3gPz778DJZWvwmUUs3ssGk"
    )
    assert (
        "d54d90bcec4146e9ae8c2ec860364f7023f33cad02b3c2bb4bdbb36689e68614"
        in ticketsForAddress
    )

    ticketVWAP = rpcClient.ticketVWAP()
    assert isinstance(ticketVWAP, float)

    txFeeInfo = rpcClient.txFeeInfo()
    assert isinstance(txFeeInfo["feeinfomempool"], rpc.FeeInfoResult)

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
