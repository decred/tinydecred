"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

DcrdataClient.endpointList() for available enpoints.
"""
from tinydecred.util import http, tinyjson
from tinydecred.pydecred import txscript
from tinydecred.crypto import crypto
from tinydecred.crypto.bytearray import ByteArray

def resultIsSuccess(res):
	"""
	JSON-decoded stake pool responses have a common base structure that enables
	a universal success check.

	Args:
		res (object): The freshly-decoded-from-JSON response.

	Returns:
		bool: True if result fields indicate success.
	"""
	return res and isinstance(res, object) and "status" in res and res["status"] == "success"

class PurchaseInfo(object):
	"""
	The PurchaseInfo models the response from the 'getpurchaseinfo' endpoint.
	This information is required for validating the pool and creating tickets.
	"""
	def __init__(self, pi):
		"""
		Args:
			pi (object): The response from the 'getpurchaseinfo' request.
		"""
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
	"""
	PoolStats models the response from the 'stats' endpoint.
	"""
	def __init__(self, stats):
		"""
		Args:
			stats (object): The response from the 'stats' request.
		"""
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
	"""
	A StakePool is a voting service provider, uniquely defined by it's URL. The
	StakePool class has methods for interacting with the VSP API. StakePool is
	JSON-serializable if used with tinyjson, so can be stored as part of an
	Account in the wallet.
	"""
	def __init__(self, url, apiKey):
		"""
		Args:
			url (string): The stake pool URL.
			apiKey (string): The API key assigned to the VSP account during
				registration.
		"""
		self.url = url
		# The network parameters are not JSON-serialized, so must be set during
		# a call to StakePool.authorize before using the StakePool.
		self.net = None
		# The signingAddress (also called a votingAddress in other contexts) is
		# the P2SH 1-of-2 multi-sig address that spends SSTX outputs.
		self.signingAddress = None
		self.apiKey = apiKey
		self.lastConnection = 0
		self.purchaseInfo = None
		self.stats = None
		self.err = None
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
	@staticmethod
	def providers(net):
		"""
		A static method to get the current Decred VSP list.

		Args:
			net (string): The network name.

		Returns:
			list(object): The vsp list.
		"""
		vsps = http.get("https://api.decred.org/?c=gsd")
		network = "testnet" if net.Name == "testnet3" else net.Name
		return [vsp for vsp in vsps.values() if vsp["Network"] == network]
	def apiPath(self, command):
		"""
		The full URL for the specified command.

		Args:
			command (string): The API endpoint specifier.

		Returns:
			string: The full URL.
		"""
		return "%s/api/v2/%s" % (self.url, command)
	def headers(self):
		"""
		Make the API request headers.

		Returns:
			object: The headers as a Python object.
		"""
		return {"Authorization": "Bearer %s" % self.apiKey}
	def validate(self, addr):
		"""
		Validate performs some checks that the PurchaseInfo provided by the
		stake pool API is valid for this given voting address. Exception is
		raised on failure to validate.

		Args:
			addr (string): The base58-encoded pubkey address that the wallet
				uses to vote.
		"""
		pi = self.purchaseInfo
		redeemScript = ByteArray(pi.script)
		scriptAddr = crypto.AddressScriptHash.fromScript(self.net.ScriptHashAddrID, redeemScript)
		if scriptAddr.string() != pi.ticketAddress:
			raise Exception("ticket address mismatch. %s != %s" % (pi.ticketAddress, scriptAddr.string()))
		# extract addresses
		scriptType, addrs, numSigs = txscript.extractPkScriptAddrs(0, redeemScript, self.net)
		if numSigs != 1:
			raise Exception("expected 2 required signatures, found 2")
		found = False
		signAddr = txscript.decodeAddress(addr, self.net)
		for addr in addrs:
			if addr.string() == signAddr.string():
				found = True
				break
		if not found:
			raise Exception("signing pubkey not found in redeem script")
	def authorize(self, address, net):
		"""
		Authorize the stake pool for the provided address and network. Exception
		is raised on failure to authorize.

		Args:
			address (string): The base58-encoded pubkey address that the wallet
				uses to vote.
			net (object): The network parameters.
		"""
		# An error is returned if the address is already set
		# {'status': 'error', 'code': 6, 'message': 'address error - address already submitted'}
		# First try to get the purchase info directly.
		self.net = net
		try:
			self.getPurchaseInfo()
			self.validate(address)
		except Exception as e:
			if "code" not in self.err or self.err["code"] != 9:
				# code 9 is address not set
				raise e
			# address is not set
			data = { "UserPubKeyAddr": address }
			res = http.post(self.apiPath("address"), data, headers=self.headers(), urlEncode=True)
			if resultIsSuccess(res):
				self.getPurchaseInfo()
				self.validate(address)
			else:
				raise Exception("unexpected response from 'address': %s" % repr(res))
	def getPurchaseInfo(self):
		"""
		Get the purchase info from the stake pool API.

		Returns:
			PurchaseInfo: The PurchaseInfo object.
		"""
		# An error is returned if the address isn't yet set
		# {'status': 'error', 'code': 9, 'message': 'purchaseinfo error - no address submitted', 'data': None}
		res = http.get(self.apiPath("getpurchaseinfo"), headers=self.headers())
		if resultIsSuccess(res):
			pi = PurchaseInfo(res["data"])
			# check the script hash
			self.purchaseInfo = pi
			return self.purchaseInfo
		self.err = res
		raise Exception("unexpected response from 'getpurchaseinfo': %r" % (res, ))
	def getStats(self):
		"""
		Get the stats from the stake pool API.

		Returns:
			Poolstats: The PoolStats object.
		"""
		res = http.get(self.apiPath("stats"), headers=self.headers())
		if resultIsSuccess(res):
			self.stats = PoolStats(res["data"])
			return self.stats
		raise Exception("unexpected response from 'stats': %s" % repr(res))
	def setVoteBits(self, voteBits):
		"""
		Set the vote preference on the StakePool.

		Returns:
			bool: True on success. Exception raised on error.
		"""
		data = { "VoteBits": voteBits }
		res = http.post(self.apiPath("voting"), data, headers=self.headers(), urlEncode=True)
		if resultIsSuccess(res):
			return True
		raise Exception("unexpected response from 'voting': %s" % repr(res))

tinyjson.register(StakePool)
