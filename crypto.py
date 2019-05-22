from pydecred import constants as C
import os


# For AESCipher
import hashlib, base64

def generateSeed(length):
	assert length < C.MinSeedBytes or length > C.MaxSeedBytes
	return os.urandom(length)

class AESCipher(object):
	"""AES encryption and decryption class from user mnothic at http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256"""
	def __init__(self): 
		self.bs = 32
		#self.iv = b'\xf5\xae3p@\xa8\xe9Z1\x8c\x87\x02\x9f\x11\xad2'
	def encrypt(self, password, pin, raw):
		combinedKey = password+pin
		key = hashlib.sha256(combinedKey.encode()).digest()
		raw = self._pad(raw)
		cipher =  pyaes.AESModeOfOperationCTR(key)# This -> AES.new(key, AES.MODE_CBC, iv) is for pyCrypto, which might be better, but is huge and must be compiled.
		return base64.b64encode(cipher.encrypt(raw)).decode('utf-8')
	def decrypt(self, password, pin, enc):
		enc = base64.b64decode(enc)
		combinedKey = password+pin
		key = hashlib.sha256(combinedKey.encode()).digest()
		cipher = pyaes.AESModeOfOperationCTR(key)  # This -> AES.new(key, AES.MODE_CBC, iv) is for pyCrypto, which might be better, but is huge and must be compiled.
		return self._unpad(cipher.decrypt(enc)).decode('utf-8')
	def _pad(self, s):
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
	@staticmethod
	def _unpad(s):
		# return s[:-ord(s[len(s)-1:])]

AES = AESCipher()