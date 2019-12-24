"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, the Decred developers
See LICENSE for details

Configuration settings for TinyDecred.
"""

import argparse
import os

from appdirs import AppDirs

from tinydecred.pydecred import nets
from tinydecred.util import helpers

# Set the data directory in a OS-appropriate location.
_ad = AppDirs("TinyDecred", False)
DATA_DIR = _ad.user_data_dir

helpers.mkdir(DATA_DIR)

# The master configuration file name.
CONFIG_NAME = "tinywallet.conf"
CONFIG_PATH = os.path.join(DATA_DIR, CONFIG_NAME)

# Some decred constants.
MAINNET = nets.mainnet.Name
TESTNET = nets.testnet.Name
SIMNET = nets.simnet.Name

# Network specific configuration settings.
MainnetConfig = {"dcrdata": "https://explorer.dcrdata.org/"}

TestnetConfig = {"dcrdata": "https://testnet.dcrdata.org/"}

SimnetConfig = {"dcrdata": "http://localhost:7777"}  # Run dcrdata locally

log = helpers.getLogger("CONFIG")  # , logLvl=0)


def tinyNetConfig(netName):
    """
    The default network parameters for the provided network name.

    Args:
        netName (str): Network name. `mainnet`, `simnet`, etc.

    Returns:
        dict: The network parameters.
    """
    if netName == MAINNET:
        return MainnetConfig
    if netName == TESTNET:
        return TestnetConfig
    if netName == SIMNET:
        return SimnetConfig
    raise Exception("unknown network")


class TinyConfig:
    """
    TinyConfig is configuration settings. The configuration file is JSON
    formatted.
    """

    def __init__(self, netName=None):
        fileCfg = helpers.fetchSettingsFile(CONFIG_PATH)
        self.file = fileCfg
        parser = argparse.ArgumentParser()
        netGroup = parser.add_mutually_exclusive_group()
        netGroup.add_argument("--simnet", action="store_true", help="use simnet")
        netGroup.add_argument("--testnet", action="store_true", help="use testnet")
        args, unknown = parser.parse_known_args()
        if unknown:
            log.warning("ignoring unknown arguments:", repr(unknown))
        self.net = None
        if netName == "simnet" or args.simnet:
            self.net = nets.simnet
        elif netName in ("testnet3", "testnet") or args.testnet:
            self.net = nets.testnet
        else:
            print("**********************************************************")
            print(" WARNING. WALLET FOR TESTING ONLY. NOT FOR USE ON MAINNET ")
            print("**********************************************************")
            self.net = nets.mainnet
        self.normalize()

    def set(self, k, v):
        """
        Set the configuration option. The configuration is not saved, so `save`
        should be called separately.

        Args:
            k (str): The setting key.
            v (JSON-encodable): The value.
        """
        self.file[k] = v

    def get(self, *keys):
        """
        Retrieve the setting at the provided key path. Multiple keys can be
        provided, with each successive key being retreived from the previous
        key's value.

        Args:
            *keys (str): Recursive key list.

        Returns:
            mixed: The configuration value.
        """
        d = self.file
        rVal = None
        for k in keys:
            if k not in d:
                return None
            rVal = d[k]
            d = rVal
        return rVal

    def normalize(self):
        """
        Perform attribute checks and initialization.
        """
        file = self.file
        netKey = "networks"
        if netKey not in file:
            file[netKey] = {}
        if self.net.Name not in file[netKey]:
            d = file[netKey][self.net.Name] = tinyNetConfig(self.net.Name)
            d["name"] = self.net.Name

    def save(self):
        """
        Save the file.
        """
        helpers.saveJSON(CONFIG_PATH, self.file, indent=4, sort_keys=True)


tinyConfig = None


def load(netName=None):
    """
    Load and return the current configuration.

    The configuration is only loaded once. Successive calls to the modular `load`
    function will return the same instance.

    Returns:
        JSON: The current configuration in JSON format.
    """
    global tinyConfig
    if not tinyConfig:
        tinyConfig = TinyConfig(netName=None)
    return tinyConfig
