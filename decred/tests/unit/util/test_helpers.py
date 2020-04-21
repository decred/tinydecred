"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import logging
import os
import os.path
from pathlib import Path
import platform

from appdirs import AppDirs

from decred import DecredError
from decred.util import helpers


def test_formatTraceback():
    # Cannot actually raise an error because pytest intercepts it.
    assert helpers.formatTraceback(DecredError("errmsg")) == "errmsg\nTraceback:\n[]"


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


def test_appDataDir(monkeypatch):
    """
    Tests appDataDir to ensure it gives expected results for various operating
    systems.

    Test adapted from dcrd TestAppDataDir.
    """
    # App name plus upper and lowercase variants.
    appName = "myapp"
    appNameUpper = appName.capitalize()
    appNameLower = appName

    # Get the home directory to use for testing expected results.
    homeDir = Path.home()

    # When we're on Windows, set the expected local and roaming directories
    # per the environment vars.  When we aren't on Windows, the function
    # should return the current directory when forced to provide the
    # Windows path since the environment variables won't exist.
    winLocal = "."
    currentOS = platform.system()
    if currentOS == "Windows":
        localAppData = os.getenv("LOCALAPPDATA")
        winLocal = Path(localAppData, appNameUpper)
    else:
        # This is kinda cheap, since this is exactly what the function does.
        # But it's all I got to pass testing when testing OS is not Windows.
        winLocal = AppDirs(appNameUpper, "").user_data_dir

    # Mac app data directory.
    macAppData = homeDir / "Library" / "Application Support"

    posixPath = Path(homeDir, "." + appNameLower)
    macPath = Path(macAppData, appNameUpper)

    """
    Tests are 3-tuples:

    opSys (str): Operating system.
    appName (str): The appDataDir argument.
    want (str): The expected result
    """
    tests = [
        # Various combinations of application name casing, leading
        # period, operating system, and roaming flags.
        ("Windows", appNameLower, winLocal),
        ("Windows", appNameUpper, winLocal),
        ("Windows", "." + appNameLower, winLocal),
        ("Windows", "." + appNameUpper, winLocal),
        ("Linux", appNameLower, posixPath),
        ("Linux", appNameUpper, posixPath),
        ("Linux", "." + appNameLower, posixPath),
        ("Linux", "." + appNameUpper, posixPath),
        ("Darwin", appNameLower, macPath),
        ("Darwin", appNameUpper, macPath),
        ("Darwin", "." + appNameLower, macPath),
        ("Darwin", "." + appNameUpper, macPath),
        ("OpenBSD", appNameLower, posixPath),
        ("OpenBSD", appNameUpper, posixPath),
        ("OpenBSD", "." + appNameLower, posixPath),
        ("OpenBSD", "." + appNameUpper, posixPath),
        ("FreeBSD", appNameLower, posixPath),
        ("FreeBSD", appNameUpper, posixPath),
        ("FreeBSD", "." + appNameLower, posixPath),
        ("FreeBSD", "." + appNameUpper, posixPath),
        ("NetBSD", appNameLower, posixPath),
        ("NetBSD", appNameUpper, posixPath),
        ("NetBSD", "." + appNameLower, posixPath),
        ("NetBSD", "." + appNameUpper, posixPath),
        ("unrecognized", appNameLower, posixPath),
        ("unrecognized", appNameUpper, posixPath),
        ("unrecognized", "." + appNameLower, posixPath),
        ("unrecognized", "." + appNameUpper, posixPath),
        # No application name provided, so expect current directory.
        ("Windows", "", "."),
        ("Linux", "", "."),
        ("Darwin", "", "."),
        ("OpenBSD", "", "."),
        ("FreeBSD", "", "."),
        ("NetBSD", "", "."),
        ("unrecognized", "", "."),
        # Single dot provided for application name, so expect current
        # directory.
        ("Windows", ".", "."),
        ("Linux", ".", "."),
        ("Darwin", ".", "."),
        ("OpenBSD", ".", "."),
        ("FreeBSD", ".", "."),
        ("NetBSD", ".", "."),
        ("unrecognized", ".", "."),
    ]

    def testplatform():
        return opSys

    monkeypatch.setattr(platform, "system", testplatform)

    for opSys, name, want in tests:
        ret = helpers.appDataDir(name)
        assert str(want) == str(ret), (opSys, name, want)

    def testexpanduser(s):
        return ""

    def testgetenv(s):
        return ""

    opSys = "Linux"
    monkeypatch.setattr(os.path, "expanduser", testexpanduser)
    monkeypatch.setattr(os, "getenv", testgetenv)
    assert helpers.appDataDir(appName) == "."
