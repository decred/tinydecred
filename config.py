"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

Configuration settings for TinyDecred.
"""
import os
import argparse
from appdirs import AppDirs
from tinydecred.util import tinyjson, helpers
from tinydecred.pydecred import mainnet, testnet, simnet

# Set the data directory in a OS-appropriate location.
_ad = AppDirs("TinyDecred", False)
DATA_DIR = _ad.user_data_dir

helpers.mkdir(DATA_DIR)

# The master configuration file name. 
CONFIG_NAME = "tinywallet.conf"
CONFIG_PATH = os.path.join(DATA_DIR, CONFIG_NAME)

# Some decred constants.
MAINNET = mainnet.Name
TESTNET = testnet.Name
SIMNET  = simnet.Name

# Network specific configuration settings.
MainnetConfig = {
    "dcrdata":  "https://explorer.dcrdata.org/"
}

TestnetConfig = {
    "dcrdata": "https://testnet.dcrdata.org/"
}

SimnetConfig = {
    "dcrdata": "http://localhost:7777" # Run dcrdata locally
}

def tinyNetConfig(netName):
    """
    The default network parameters for the provided network name.

    Args:
        netName (str): Network name. `mainnet`, `simnet`, etc.

    Returns:
        obj: The network parameters.
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
    TinyConfig is configuration settings. The configuration file JSON formatted.
    """
    def __init__(self):
        fileCfg = helpers.fetchSettingsFile(CONFIG_PATH)
        self.file = fileCfg
        parser = argparse.ArgumentParser()
        netGroup = parser.add_mutually_exclusive_group()
        netGroup.add_argument("--simnet", action='store_true', help="use simnet")
        netGroup.add_argument("--testnet", action='store_true', help="use testnet")
        args = parser.parse_args()
        self.net = None
        if args.simnet:
            self.net = simnet
        elif args.testnet:
            self.net = testnet
        else:
            self.net = mainnet
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
        tinyjson.save(CONFIG_PATH, self.file)

# The configuration is only loaded once. Successive calls to the modular `load`
# function will return the same instance.
tinyConfig = TinyConfig()

def load():
    return tinyConfig




