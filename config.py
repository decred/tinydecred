from tinydecred.pydecred import mainnet, testnet, simnet, dcrjson as json, helpers
from appdirs import AppDirs
import os
import argparse

_ad = AppDirs("TinyDecred", False)
DATA_DIR = _ad.user_data_dir
helpers.mkdir(DATA_DIR)
CONFIG_NAME = "tinywallet.conf"
CONFIG_PATH = os.path.join(DATA_DIR, CONFIG_NAME)
MAINNET = mainnet.Name
TESTNET = testnet.Name
SIMNET  = simnet.Name

MainnetConfig = {
	"dcrdatas": [
		"https://explorer.dcrdata.org/"
	]
}

TestnetConfig = {
	"dcrdatas": [
		"https://testnet.dcrdata.org/"
	]
}

SimnetConfig = {
	"dcrdatas": [
		"http://localhost:7777" # Run dcrdata locally
	]
}

def tinyNetConfig(netName):
	if netName == MAINNET:
		return MainnetConfig
	if netName == TESTNET:
		return TestnetConfig
	if netName == SIMNET:
		return SimnetConfig
	raise Exception("unknown network")

class TinyConfig:
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
	
	def dcrdatas(self):
		return self.tinyConfig["dcrdata"]
	def normalize(self):
		file = self.file
		if self.net is None:
			if "network" in file:
				netName = file["network"]
				if netName == MAINNET:
					self.net = mainnet
				elif netName == TESTNET:
					self.net = testnet
				elif netName == SIMNET:
					self.net = simnet
			else:
				file["network"] = MAINNET
				self.net = mainnet
		netKey = "networks"
		if netKey not in file:
			file[netKey] = {}
		if self.net.Name not in file[netKey]:
			d = file[netKey][self.net.Name] = tinyNetConfig(self.net.Name)
			d["name"] = self.net.Name
	def save(self):
		json.save(CONFIG_PATH, self.file)

tinyConfig = None	
def load():
	global tinyConfig
	if not tinyConfig:
		tinyConfig = TinyConfig()
	return tinyConfig




