from tinydecred.pydecred import constants as C
import os

def generateSeed(length=C.MaxSeedBytes):
	assert length >= C.MinSeedBytes and length <= C.MaxSeedBytes
	return os.urandom(length)
