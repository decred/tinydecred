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
    searchRawTransactions = rpcClient.searchRawTransactions(
        "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx"
    )
    assert isinstance(searchRawTransactions[0], rpc.SearchRawTransactionsResult)

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
    assert ticketVWAP

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
