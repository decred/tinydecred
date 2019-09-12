"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

DcrdataClient.endpointList() for available enpoints.
"""
import unittest
from tinydecred.util import http, tinyjson
from tinydecred.pydecred import txscript
from tinydecred.crypto import crypto, opcode
from tinydecred.crypto.bytearray import ByteArray

def resultIsSuccess(res):
		return res and isinstance(res, object) and "status" in res and res["status"] == "success"

class PurchaseInfo(object):
	def __init__(self, pi):
		get = lambda k, default=None: pi[k] if k in pi else default
		self.poolAddress = get("PoolAddress")
		self.poolFees = get("PoolFees")
		self.script = get("Script")
		self.ticketAddress = get("TicketAddress")
		self.voteBits = get("VoteBits")
		self.voteBitsVersion = get("VoteBitsVersion")
	def __tojson__(self):
		# using upper-camelcase to match keys in api response
		return {
			"PoolAddress": self.poolAddress,
			"PoolFees": self.poolFees,
			"Script": self.script,
			"TicketAddress": self.ticketAddress,
			"VoteBits": self.voteBits,
			"VoteBitsVersion": self.voteBitsVersion,
		}
	@staticmethod
	def __fromjson__(obj):
		return PurchaseInfo(obj)

tinyjson.register(PurchaseInfo)

class PoolStats(object):
	def __init__(self, stats):
		get = lambda k, default=None: stats[k] if k in stats else default
		self.allMempoolTix = get("AllMempoolTix")
		self.apiVersionsSupported = get("APIVersionsSupported")
		self.blockHeight = get("BlockHeight")
		self.difficulty = get("Difficulty")
		self.expired = get("Expired")
		self.immature = get("Immature")
		self.live = get("Live")
		self.missed = get("Missed")
		self.ownMempoolTix = get("OwnMempoolTix")
		self.poolSize = get("PoolSize")
		self.proportionLive = get("ProportionLive")
		self.proportionMissed = get("ProportionMissed")
		self.revoked = get("Revoked")
		self.totalSubsidy = get("TotalSubsidy")
		self.voted = get("Voted")
		self.network = get("Network")
		self.poolEmail = get("PoolEmail")
		self.poolFees = get("PoolFees")
		self.poolStatus = get("PoolStatus")
		self.userCount = get("UserCount")
		self.userCountActive = get("UserCountActive")
		self.version = get("Version")
	def __tojson__(self):
		return {
			"AllMempoolTix": self.allMempoolTix,
			"APIVersionsSupported": self.apiVersionsSupported,
			"BlockHeight": self.blockHeight,
			"Difficulty": self.difficulty,
			"Expired": self.expired,
			"Immature": self.immature,
			"Live": self.live,
			"Missed": self.missed,
			"OwnMempoolTix": self.ownMempoolTix,
			"PoolSize": self.poolSize,
			"ProportionLive": self.proportionLive,
			"ProportionMissed": self.proportionMissed,
			"Revoked": self.revoked,
			"TotalSubsidy": self.totalSubsidy,
			"Voted": self.voted,
			"Network": self.network,
			"PoolEmail": self.poolEmail,
			"PoolFees": self.poolFees,
			"PoolStatus": self.poolStatus,
			"UserCount": self.userCount,
			"UserCountActive": self.userCountActive,
			"Version": self.version,
		}
	@staticmethod
	def __fromjson__(obj):
		return PoolStats(obj)

tinyjson.register(PoolStats)

class StakePool(object):
	def __init__(self, url, apiKey):
		self.url = url
		self.signingAddress = None
		self.apiKey = apiKey
		self.lastConnection = 0
		self.purchaseInfo = None
		self.stats = None
	def __tojson__(self):
		return {
			"url": self.url,
			"apiKey": self.apiKey,
			"purchaseInfo": self.purchaseInfo,
			"stats": self.stats,
		}
	@staticmethod
	def __fromjson__(obj):
		sp = StakePool(obj["url"], obj["apiKey"])
		sp.purchaseInfo = obj["purchaseInfo"]
		sp.stats = obj["stats"]
		return sp
	def apiPath(self, command):
		return "%s/api/v2/%s" % (self.url, command)
	def headers(self):
		return {"Authorization": "Bearer %s" % self.apiKey}
	def setAddress(self, address):
		data = { "UserPubKeyAddr": address }
		res = http.post(self.apiPath("address"), data, headers=self.headers(), urlEncode=True)
		if resultIsSuccess(res):
			self.signingAddress = address
		else:
			raise Exception("unexpected response from 'address': %s" % repr(res))
	def getPurchaseInfo(self, net):
		res = http.get(self.apiPath("getpurchaseinfo"), headers=self.headers())
		if resultIsSuccess(res):
			pi = PurchaseInfo(res["data"])
			# check the script hash
			redeemScript = ByteArray(pi.script)
			scriptAddr = crypto.AddressScriptHash.fromScript(net.ScriptHashAddrID, redeemScript)
			if scriptAddr.string() != pi.ticketAddress:
				raise Exception("ticket address mismatch. %s != %s" % (pi.ticketAddress, scriptAddr.string()))
			# extract addresses
			scriptType, addrs, numSigs = txscript.extractPkScriptAddrs(0, redeemScript, net)
			if numSigs != 1:
				raise Exception("expected 2 required signatures, found 2")
			found = False
			signAddr = txscript.decodeAddress(self.signingAddress, net)
			for addr in addrs:
				if addr.string() == signAddr.string():
					found = True
					break
			if not found:
				raise Exception("signing pubkey not found in redeem script")
			self.purchaseInfo = pi
			return self.purchaseInfo
		raise Exception("unexpected response from 'getpurchaseinfo': %r" % (res, ))
	def getStats(self):
		res = http.get(self.apiPath("stats"), headers=self.headers())
		if resultIsSuccess(res):
			self.stats = PoolStats(res["data"])
			return self.stats
		raise Exception("unexpected response from 'stats': %s" % repr(res))
	def setVoteBits(self, voteBits):
		data = { "VoteBits": voteBits }
		res = http.post(self.apiPath("voting"), data, headers=self.headers(), urlEncode=True)
		if resultIsSuccess(res):
			return True
		raise Exception("unexpected response from 'voting': %s" % repr(res))

tinyjson.register(StakePool)

