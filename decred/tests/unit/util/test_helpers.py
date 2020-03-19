"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import logging

from decred.util import helpers


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
