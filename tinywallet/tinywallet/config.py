"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details

Configuration settings for TinyDecred.
"""

import argparse
import logging
import os
import sys

from appdirs import AppDirs

from decred.dcr import nets
from decred.util import helpers


# Set the data directory in a OS-appropriate location.
_ad = AppDirs("TinyWallet", False)
DATA_DIR = _ad.user_data_dir

helpers.mkdir(DATA_DIR)

# The master configuration file name.
CONFIG_NAME = "tinywallet.conf"
CONFIG_PATH = os.path.join(DATA_DIR, CONFIG_NAME)

# Some decred constants.
MAINNET = nets.mainnet.Name
TESTNET = nets.testnet.Name
SIMNET = nets.simnet.Name

logLevelMap = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "debug": logging.DEBUG,
    "notset": logging.NOTSET,
    "0": logging.NOTSET,
}


def logLvl(s):
    """
    Get the log level from the map.

    Args:
        s (str): A string which is a key for the logLevelMap. Case-insensitive.
    """
    return logLevelMap[s.lower()]


# Some network specific default settings.
NetworkDefaults = {
    MAINNET: {"dcrdata": "https://explorer.dcrdata.org/"},
    TESTNET: {"dcrdata": "https://testnet.dcrdata.org/"},
    SIMNET: {"dcrdata": "http://localhost:17779"},
}


class CmdArgs:
    """
    CmdArgs are command-line configuration options.
    """

    def __init__(self):
        self.logLevel = logging.INFO
        self.moduleLevels = {}
        parser = argparse.ArgumentParser()
        parser.add_argument("--loglevel")
        netGroup = parser.add_mutually_exclusive_group()
        netGroup.add_argument("--simnet", action="store_true", help="use simnet")
        netGroup.add_argument("--testnet", action="store_true", help="use testnet")
        args, unknown = parser.parse_known_args()
        if unknown:
            sys.exit(f"unknown arguments: {unknown}")
        self.netParams = nets.mainnet
        if args.simnet:
            self.netParams = nets.simnet
        elif args.testnet:
            self.netParams = nets.testnet
        else:
            print("**********************************************************")
            print(" WARNING. WALLET FOR TESTING ONLY. NOT FOR USE ON MAINNET ")
            print("**********************************************************")
        if args.loglevel:
            try:
                if any(ch in args.loglevel for ch in (",", ":")):
                    pairs = (s.split(":") for s in args.loglevel.split(","))
                    self.moduleLevels = {k: logLvl(v) for k, v in pairs}
                else:
                    self.logLevel = logLvl(args.loglevel)
            except Exception:
                sys.exit(f"malformed loglevel specifier: {args.loglevel}")


class DB:
    """Various database keys used by tinywallet modules"""

    wallet = "wallet".encode()
    theme = "theme".encode()
    dcrdata = "dcrdata".encode()
    rpcuser = "rpcuser".encode()
    rpcpass = "rpcpass".encode()
    rpccert = "rpccert".encode()
    rpchost = "rpchost".encode()
    dcrdon = "dcrdon".encode()


def dcrd(netParams):
    """
    Attempt to fetch the dcrd configuration settings. Values will be parsed for
    'rpcuser', 'rpcpass', 'rpclisten', and 'rpccert'. The setting for 'rpcuser'
    must be present in the file. If values are not found for 'rpccert' or
    'rpclisten', default locations are populated.

    Args:
        netParams (bool): The network parameters.

    Returns:
        dict or None: The parsed configuration settings.
    """
    dcrdCfgDir = helpers.appDataDir("dcrd")
    cfgPath = os.path.join(dcrdCfgDir, "dcrd.conf")
    if not os.path.isfile(cfgPath):
        return {}
    dcrdCfg = helpers.readINI(cfgPath, ["rpclisten", "rpcuser", "rpcpass", "rpccert"])
    if "rpcuser" not in dcrdCfg:
        return None
    if "rpccert" not in dcrdCfg:
        dcrdCfg["rpccert"] = os.path.join(dcrdCfgDir, "rpc.cert")
    # Tinywallet uses the protocol (scheme) of the URL for now.
    if "rpclisten" in dcrdCfg:
        dcrdCfg["rpclisten"] = "https://" + dcrdCfg["rpclisten"]
    else:
        dcrdCfg["rpclisten"] = f"https://localhost:{nets.DcrdPorts[netParams.Name]}"
    return dcrdCfg


tinyConfig = None


def load():
    """
    Load and return the current command-line configuration. The configuration is
    only loaded once. Successive calls to the modular `load` function will
    return the same instance.

    Returns:
        CmdArgs: The current command-line configuration.
    """
    global tinyConfig
    if not tinyConfig:
        tinyConfig = CmdArgs()
    return tinyConfig
