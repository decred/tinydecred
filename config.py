from pydecred import helpers
from appdirs import AppDirs
import os
from pydecred import mainnet, testnet
import json

_ad = AppDirs("TinyWallet", "SciCo", version="0.0")
DATA_DIR = _ad.user_data_dir
helpers.mkdir(DATA_DIR)
CONFIG_NAME = "tinywallet.conf"
CONFIG_PATH = os.path.join(DATA_DIR, CONFIG_NAME)
MAINNET = "mainnet"
TESTNET = "testnet3"

MainnetConfig = {
	"dcrdata": [
		"https://explorer.dcrdata.org/"
	]
}

TestnetConfig = {
	"dcrdata": [
		"https://testnet.dcrdata.org/"
	]
}

class WalletConfig:
	def __init__(self):
		fileCfg = helpers.fetchSettingsFile(CONFIG_PATH)
		self.file = fileCfg
		self.net = None
		if "network" in fileCfg:
			netName = fileCfg["network"]
			if netName == MAINNET:
				self.net = mainnet
			elif netName == TESTNET:
				self.net = testnet
		self.dcrdata = None
	def set(self, k, v):
		self.file[k] = v
	def get(self, k):
		if k in self.file:
			return self.file[k]
		return None
	def save(self):
		helpers.saveFile(DATA_DIR, CONFIG_NAME, json.dumps(self.file))

	
def load():
	return WalletConfig()




