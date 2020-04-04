"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os
import random

import pytest

from decred.util import chains, helpers


@pytest.fixture
def sign():
    def _sign(x):
        """
        x: number
        """
        if x < 0:
            return -1
        elif x > 0:
            return 1
        else:
            return 0

    return _sign


# Seed initialization is delegated to tests.
# random.seed(0)


@pytest.fixture
def randBytes():
    def _randBytes(low=0, high=50):
        return bytes(random.randint(0, 255) for _ in range(random.randint(low, high)))

    return _randBytes


@pytest.fixture(scope="module")
def prepareLogger(request):
    helpers.prepareLogging()


@pytest.fixture(scope="class")
def registerChain(request):
    chains.registerChain("dcr", None)


@pytest.fixture(scope="session")
def dcrdConfig():
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
