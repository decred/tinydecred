"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

import calendar
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import time
import traceback


def formatTraceback(err):
    """
    Format a traceback for an error.

    Args:
        err (BaseException): The error the traceback is extracted from.

    Returns:
        str: The __str__() of the traceback, followed by the standard formatting
            of the traceback on the following lines.
    """
    return f"{err}\n{traceback.print_tb(err.__traceback__)}"


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
