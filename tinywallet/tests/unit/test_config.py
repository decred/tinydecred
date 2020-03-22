"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import logging
import sys

from tinywallet.config import CmdArgs


def test_CmdArgs():
    sys.argv = ["cmd", "--simnet"]
    cfg = CmdArgs()
    assert cfg.netParams.Name == "simnet"

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
