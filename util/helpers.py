"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details
"""

import calendar
import logging
from logging.handlers import RotatingFileHandler
import os
import shutil
import sys
from tempfile import TemporaryDirectory
import time
import traceback
from os.path import expanduser
import platform
from appdirs import AppDirs
import configparser

from tinydecred.util import tinyjson


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


def recursiveUpdate(target, source):
    """
    Recursively update the target dictionary with the source dictionary, leaving
    unfound keys in place. This is different than dict.update, which removes
    target keys not in the source.

    :param dict target: The dictionary to be updated
    :param dict source: The dictionary to be integrated
    :return: target dict is returned as a convenience. This function updates the
        target dict in place.
    :rtype: dict
    """
    for k, v in source.items():
        if isinstance(v, dict):
            target[k] = recursiveUpdate(target.get(k, {}), v)
        else:
            target[k] = v
    return target


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


rootLogger = logging.getLogger("")
rootLogger.setLevel(logging.NOTSET)


def prepareLogger(name, filepath=None, logLvl=logging.INFO):
    """
    Set logger settings appropriately
    """
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
        # fileHandler.setLevel(logLvl)
        rootLogger.addHandler(fileHandler)
    if sys.executable and os.path.split(sys.executable)[1] == "pythonw.exe":
        # disabling stdout printing for pythonw
        pass
    else:
        # skip adding the stdout handler for pythonw in windows
        printHandler = logging.StreamHandler()
        printHandler.setFormatter(log_formatter)
        # printHandler.setLevel(1)
        rootLogger.addHandler(printHandler)
    return getLogger(name, logLvl)


def getLogger(name, logLvl=logging.INFO):
    l = rootLogger.getChild(name)
    l.setLevel(logLvl)
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
    Fetches the JSON settings file, creating an empty json object if necessary
    """
    if not os.path.isfile(filepath):
        with open(filepath, "w+") as file:
            file.write("{}")
    return tinyjson.loadFile(filepath)


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
    file. All sections will be searched. An object with discovered keys and
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
