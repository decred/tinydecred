"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

import calendar
import configparser
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import sys
import time
import traceback
from urllib.parse import urlsplit, urlunsplit

from appdirs import AppDirs


def formatTraceback(err):
    """
    Format a traceback for an error so that it can go into logs.

    Args:
        err (BaseException): The error the traceback is extracted from.

    Returns:
        str: The __str__() of the error, followed by the standard formatting
            of the traceback on the following lines.
    """
    return "".join(traceback.format_exception(None, err, err.__traceback__))


def mkdir(path):
    """
    Create the directory if it doesn't exist. Uses os.path .

    Args:
        path (str, bytes): the directory path.
    """
    if os.path.isdir(path):
        return True
    if os.path.isfile(path):
        return False
    os.makedirs(path)
    return True


def mktime(year, month=None, day=None):
    """
    Make a timestamp from year, month, day.

    Args:
        year (int): the year.
        month (int), optional: the month.
        day (int), optional: the day.
    """
    if month:
        if day:
            return calendar.timegm(
                time.strptime(
                    "%i-%s-%s" % (year, str(month).zfill(2), str(day).zfill(2)),
                    "%Y-%m-%d",
                )
            )
        return calendar.timegm(
            time.strptime("%i-%s" % (year, str(month).zfill(2)), "%Y-%m")
        )
    return calendar.timegm(time.strptime(str(year), "%Y"))


class LogSettings:
    """Used to track a few logging-related settings"""

    root = logging.getLogger("")
    defaultLevel = logging.INFO
    moduleLevels = {}
    loggers = {}


LogSettings.root.setLevel(logging.NOTSET)


def prepareLogging(filepath=None, logLvl=logging.INFO, lvlMap=None):
    """
    Prepare for using getLogger. Logs to stdout. If filepath is provided, log
    outputs will be saved to a rotating log file at the specified location. Any
    loggers, both future loggers and those already created, will have their
    levels set according to the new logLvl and lvlMap.

    Args:
        filepath (str or pathlib.Path): optional. The base name for the rotating
            log file.
        logLvl (int): optional. default logging.INFO. The default logging level
            used for all new loggers without entries in the lvlMap.
        lvlMap: (dict): optional. If provided, the name->level mapping will be
            added to the stored level dict, which is referenced when loggers are
            created using getLogger.
    """
    # Set log level for existing loggers.
    LogSettings.defaultLevel = logLvl
    LogSettings.moduleLevels.update(lvlMap if lvlMap else {})
    for name, logger in LogSettings.loggers.items():
        if name in LogSettings.moduleLevels:
            logger.setLevel(LogSettings.moduleLevels[name])
        else:
            logger.setLevel(LogSettings.defaultLevel)

    log_formatter = logging.Formatter(
        "%(asctime)s %(module)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s"
    )
    if filepath:
        fileHandler = RotatingFileHandler(
            filepath,
            mode="a",
            maxBytes=5 * 1024 * 1024,
            backupCount=2,
            encoding=None,
            delay=False,
        )
        fileHandler.setFormatter(log_formatter)
        LogSettings.root.addHandler(fileHandler)
    if not sys.executable.endswith("pythonw.exe"):
        # Skip adding the stdout handler for pythonw in windows.
        printHandler = logging.StreamHandler()
        printHandler.setFormatter(log_formatter)
        LogSettings.root.addHandler(printHandler)


def getLogger(name):
    """
    Gets a named logger. If the name has a log level registered with
    prepareLogger, that level will be used, otherwise the default is used.

    Args:
        name (str): The logger name.
    """
    l = LogSettings.root.getChild(name)
    l.setLevel(LogSettings.moduleLevels.get(name, LogSettings.defaultLevel))
    LogSettings.loggers[name] = l
    return l


def readINI(path, keys):
    """
    Attempt to read the specified keys from the INI-formatted configuration
    file. All sections will be searched. A dict with discovered keys and
    values will be returned. If a key is not discovered, it will not be
    present in the result.

    Args:
        path (str): The path to the INI configuration file.
        keys (list(str)): Keys to search for.

    Returns:
        dict: Discovered keys and values.
    """
    config = configparser.ConfigParser()
    # Need to add a section header since configparser doesn't handle sectionless
    # INI format.
    with open(path) as f:
        config.read_string("[tinydecred]\n" + f.read())  # This line does the trick.
    res = {}
    for section in config.sections():
        for k in config[section]:
            if k in keys:
                res[k] = config[section][k]
    return res


def appDataDir(appName):
    """
    appDataDir returns an operating system specific directory to be used for
    storing application data for an application.
    """
    if appName == "" or appName == ".":
        return "."

    # The caller really shouldn't prepend the appName with a period, but
    # if they do, handle it gracefully by stripping it.
    appName = appName.lstrip(".")
    appNameUpper = appName.capitalize()
    appNameLower = appName.lower()

    # Get the OS specific home directory.
    homeDir = os.path.expanduser("~")

    # Fall back to standard HOME environment variable that works
    # for most POSIX OSes.
    if homeDir == "":
        homeDir = os.getenv("HOME")

    opSys = platform.system()
    if opSys == "Windows":
        # Windows XP and before didn't have a LOCALAPPDATA, so fallback
        # to regular APPDATA when LOCALAPPDATA is not set.
        return AppDirs(appNameUpper, "").user_data_dir

    elif opSys == "Darwin":
        if homeDir != "":
            return os.path.join(homeDir, "Library", "Application Support", appNameUpper)

    else:
        if homeDir != "":
            return os.path.join(homeDir, "." + appNameLower)

    # Fall back to the current directory if all else fails.
    return "."


def makeWebsocketURL(baseURL, path):
    """
    Turn the HTTP/HTTPS URL into a WS/WSS one.

    Args:
        url (str): The base URL.
        path (str): The websocket endpoint path. e.g. path of "ws" will yield
            URL wss://yourhost.com/ws.
    Returns:
        string: the WebSocket URL.
    """
    url = urlsplit(baseURL)
    scheme = "wss" if url.scheme in ("https", "wss") else "ws"
    return urlunsplit((scheme, url.netloc, f"/{path}", "", ""))
