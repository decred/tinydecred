from pydecred import helpers
from appdirs import AppDirs
import os
from pydecred import mainnet, testnet, json

_ad = AppDirs("TinyDecred", "SciCo")
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

class TinyConfig:
	def __init__(self):
		fileCfg = helpers.fetchSettingsFile(CONFIG_PATH)
		self.file = fileCfg
		self.normalize()
	def set(self, k, v):
		self.file[k] = v
	def get(self, *keys):
		d = self.file
		rVal = None
		for k in keys:
			if k not in d:
				return None
			rVal = d[k]
			d = rVal
		return rVal
	def normalize(self):
		self.net = None
		cfg = self.file
		if "network" in cfg:
			netName = cfg["network"]
			if netName == MAINNET:
				self.net = mainnet
			elif netName == TESTNET:
				self.net = testnet
	def save(self):
		json.save(CONFIG_PATH, self.file)

	
def load():
	return TinyConfig()




