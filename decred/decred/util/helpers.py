"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

import calendar
import configparser
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from os.path import expanduser
import platform
import shutil
import sys
from tempfile import TemporaryDirectory
import time
import traceback
import webbrowser

from appdirs import AppDirs


def coinify(atoms):
    """
    Convert the smallest unit of a coin into its coin value.

    Args:
        atoms (int): 1e8 division of a coin.

    Returns:
        float: The coin value.
    """
    return round(atoms / 1e8, 8)


def normalizeNetName(netName):
    """
    Remove the numerals from testnet.

    Args:
        netName (string): The raw network name.

    Returns:
        string: The network name with numerals stripped.
    """
    return "testnet" if netName == "testnet3" else netName


def openInBrowser(url):
    """
    Open url in the users browser

    Args:
        url (string): the url to open.
    """
    webbrowser.open(url, new=2)


def formatTraceback(e):
    """
    Format a traceback for an exception.

    Returns:
        str: The __str__() of the traceback, followed by the standard formatting
            of the traceback on the following lines.
    """
    return "%s\n%s" % (e, traceback.print_tb(e.__traceback__))


def mkdir(path):
    """
    Create the directory if it doesn't exist.
    """
    if os.path.isdir(path):
        return True
    if os.path.isfile(path):
        return False
    os.makedirs(path)
    return True


def moveFile(ogPath, newPath):
    """
    Move a file.

    Args:
        ogPath (str): The filepath of the file to move.
        newPath (str): The destination filepath.
    """
    shutil.move(ogPath, newPath)


def yearmonthday(t):
    """
    Returns a tuple (year, month, day) with 1 <= month <= 12
    and 1 <= day <= 31
    """
    return tuple(int(x) for x in time.strftime("%Y %m %d", time.gmtime(t)).split())


def mktime(year, month=None, day=None):
    """
    Make a timestamp from year, month, day. See `yearmonthday`.
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


class Benchmarker:
    """
    A class for basic execution timing.
    """

    on = False

    def __init__(self, startStr=None):
        if not self.on:
            return
        if startStr:
            print(startStr)
        self.start()

    def start(self):
        if self.on:
            tNow = time.time() * 1000
            self.startTime = tNow
            self.lapTime = tNow

    def resetLap(self):
        if self.on:
            tNow = time.time() * 1000
            self.lapTime = tNow

    def lap(self, identifier):
        if self.on:
            tNow = time.time() * 1000
            print("  %i ms to %s" % (int(tNow - self.lapTime), identifier))
            self.resetLap()

    def end(self, identifier):
        if self.on:
            tNow = time.time() * 1000
            print("%i ms to %s" % (int(tNow - self.startTime), identifier))
            self.start()


def formatNumber(number, billions="B", spacer=" ", isMoney=False):
    """
    Format the number to a string with max 3 sig figs, and appropriate unit
    multipliers.

    Args:
        number (float or int):  The number to format.
        billions (str): Default "G". The unit multiplier to use for billions.
            "B" is also common.
        spacer (str): Default " ". A spacer to insert between the number and
            the unit multiplier. Empty string also common.
        isMoney (bool): If True, a number less than 0.005 will always be 0.00,
            and a number will never be formatted with just one decimal place.
    """
    if number == 0:
        return "0%s" % spacer

    absVal = float(abs(number))
    flt = float(number)
    if absVal >= 1e12:  # >= 1 trillion
        return "%.2e" % flt
    if absVal >= 10e9:  # > 10 billion
        return "%.1f%s%s" % (flt / 1e9, spacer, billions)
    if absVal >= 1e9:  # > 1 billion
        return "%.2f%s%s" % (flt / 1e9, spacer, billions)
    if absVal >= 100e6:  # > 100 million
        return "%i%sM" % (int(round(flt / 1e6)), spacer)
    if absVal >= 10e6:  # > 10 million
        return "%.1f%sM" % (flt / 1e6, spacer)
    if absVal >= 1e6:  # > 1 million
        return "%.2f%sM" % (flt / 1e6, spacer)
    if absVal >= 100e3:  # > 100 thousand
        return "%i%sk" % (int(round(flt / 1e3)), spacer)
    if absVal >= 10e3:  # > 10 thousand
        return "%.1f%sk" % (flt / 1e3, spacer)
    if absVal >= 1e3:  # > 1 thousand
        return "%.2f%sk" % (flt / 1e3, spacer)
    if isinstance(number, int):
        return "%i" % number
    if absVal >= 100:
        return "%i%s" % (flt, spacer)
    if absVal >= 10:
        if isMoney:
            return "%.2f%s" % (
                flt,
                spacer,
            )  # Extra degree of precision here because otherwise money looks funny.
        return "%.1f%s" % (
            flt,
            spacer,
        )  # Extra degree of precision here because otherwise money looks funny.
    # if absVal > 1:
    #   return "%.2f%s" % (absVal, spacer)
    if absVal > 0.01:
        return "%.2f%s" % (flt, spacer)
    if isMoney:
        return "0.00%s" % spacer
    return ("%.2e%s" % (flt, spacer)).replace("e-0", "e-")


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
            delay=0,
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


class ConsoleLogger:
    """
    A logger that only prints to stdout.
    """

    @staticmethod
    def log(s):
        print(s)

    debug = log
    info = log
    warning = log
    error = log
    critical = log


def fetchSettingsFile(filepath):
    """
    Fetches the JSON settings file, creating an empty JSON object if necessary.
    """
    if not os.path.isfile(filepath):
        with open(filepath, "w+") as file:
            file.write("{}")
    return loadJSON(filepath)


def saveFile(path, contents, binary=False):
    """
    Atomic file save.
    """
    with TemporaryDirectory() as tempDir:
        tmpPath = os.path.join(tempDir, "tmp.tmp")
        with open(tmpPath, "wb" if binary else "w") as f:
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmpPath, path)


def appDataDir(appName):
    """
    appDataDir returns an operating system specific directory to be used for
    storing application data for an application.
    """
    if appName == "" or appName == ".":
        return "."

    # The caller really shouldn't prepend the appName with a period, but
    # if they do, handle it gracefully by stripping it.
    appName = appName.lstrip()
    appNameUpper = appName.capitalize()
    appNameLower = appName.lower()

    # Get the OS specific home directory.
    homeDir = expanduser("~")

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


def saveJSON(filepath, thing, **kwargs):
    """
    Save the object to JSON.
    """
    saveFile(filepath, json.dumps(thing, **kwargs))


def loadJSON(filepath):
    """
    Load the JSON file into a Python dict or list.
    """
    with open(filepath, "r") as f:
        return json.loads(f.read())
