"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import logging
import sys

import pytest

from decred.dcr.nets import simnet
from decred.util import helpers
from tinywallet import ui  # noqa, for coverage.
from tinywallet.config import CmdArgs, dcrd, load


def test_CmdArgs():
    sys.argv = ["cmd", "--unknown"]
    with pytest.raises(SystemExit):
        cfg = CmdArgs()

    sys.argv = ["cmd", "--simnet"]
    cfg = CmdArgs()
    assert cfg.netParams.Name == "simnet"

    sys.argv = ["cmd", "--testnet", "--loglevel", ",:"]
    with pytest.raises(SystemExit):
        cfg = CmdArgs()

    sys.argv = ["cmd", "--testnet", "--loglevel", "debug"]
    cfg = CmdArgs()
    assert cfg.netParams.Name == "testnet3"
    assert cfg.logLevel == logging.DEBUG

    sys.argv = ["cmd", "--loglevel", "A:Warning,B:deBug,C:Critical,D:0"]
    cfg = CmdArgs()
    assert len(cfg.moduleLevels) == 4
    assert cfg.moduleLevels["A"] == logging.WARNING
    assert cfg.moduleLevels["B"] == logging.DEBUG
    assert cfg.moduleLevels["C"] == logging.CRITICAL
    assert cfg.moduleLevels["D"] == logging.NOTSET


def test_dcrd(monkeypatch, tmpdir):
    def mock_appDataDir(app_name):
        return tmpdir

    monkeypatch.setattr(helpers, "appDataDir", mock_appDataDir)
    assert dcrd(simnet) == {}

    cfg_file = tmpdir.join("dcrd.conf")

    cfg_file.write("")
    assert dcrd(simnet) is None

    cfg_file.write("rpcuser=username\n")
    cfg = dcrd(simnet)
    assert "rpc.cert" in cfg["rpccert"]
    assert "localhost" in cfg["rpclisten"]

    cfg_file.write("rpcuser=username\nrpclisten=listen\n")
    assert "listen" in dcrd(simnet)["rpclisten"]


def test_load():
    assert isinstance(load(), CmdArgs)
