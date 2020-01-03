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

    validateAddress = rpcClient.validateAddress("DsUxwT6Kbiur6Nps9q3uGEpJCvrhcxX2nii")
    assert isinstance(validateAddress, rpc.ValidateAddressChainResult)

    verifyChain = rpcClient.verifyChain()
    assert isinstance(verifyChain, rpc.VerifyChainResult)

    verifyMessage = rpcClient.verifyMessage(
        "DsUxwT6Kbiur6Nps9q3uGEpJCvrhcxX2nii",
        "H166ndZLNEpIXrcEm4V9lf+AizRp/ejCAhs21J/ht87/RK0QFnOscCbJixKok3oHjpOS0jAkJ4jFktqMXD59LU8=",
        "this decred is tiny",
    )
    assert isinstance(verifyMessage, rpc.VerifyMessageResult)

    version = rpcClient.version()
    assert isinstance(version, rpc.VersionResult)
