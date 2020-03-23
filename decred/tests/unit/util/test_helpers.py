"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import logging
import os

from decred import DecredError
from decred.util import helpers


def test_formatTraceback():
    # Cannot actually raise an error because pytest intercepts it.
    assert helpers.formatTraceback(DecredError("errmsg")) == "errmsg\nNone"


def test_mkdir(tmp_path):
    fpath = tmp_path / "test_file"
    f = open(fpath, "w")
    f.close()
    assert not helpers.mkdir(fpath)
    dpath = tmp_path / "test_dir"
    assert helpers.mkdir(dpath)
    assert os.path.isdir(dpath)
    assert helpers.mkdir(dpath)


def test_mktime():
    assert helpers.mktime(1970) == 0
    assert helpers.mktime(1970, month=None, day=1) == 0
    assert helpers.mktime(1970, month=1) == 0
    assert helpers.mktime(1970, month=1, day=1) == 0
    assert helpers.mktime(1970, month=2) == 2678400
    assert helpers.mktime(1970, month=2, day=1) == 2678400
    assert helpers.mktime(1970, month=2, day=2) == 2764800


def test_prepareLogging(tmp_path):
    path = tmp_path / "test.log"
    helpers.prepareLogging(filepath=path)
    logger = helpers.getLogger("1")
    logger1 = logger
    assert logger.getEffectiveLevel() == logging.INFO

    logger.info("something")
    assert path.is_file()

    helpers.prepareLogging(filepath=path, logLvl=logging.DEBUG)
    logger = helpers.getLogger("2")
    assert logger.getEffectiveLevel() == logging.DEBUG

    helpers.prepareLogging(
        filepath=path,
        logLvl=logging.INFO,
        lvlMap={"1": logging.NOTSET, "3": logging.WARNING},
    )
    logger = helpers.getLogger("3")
    assert logger.getEffectiveLevel() == logging.WARNING
    assert logger1.getEffectiveLevel() == logging.NOTSET
