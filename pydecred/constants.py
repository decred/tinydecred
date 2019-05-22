# A few useful constants.
import os

PYDECRED_PACKAGEDIR =  os.path.dirname(os.path.realpath(__file__))
FONTDIR = os.path.join(PYDECRED_PACKAGEDIR, "fonts")
FAVICON = os.path.join(PYDECRED_PACKAGEDIR, "favicon-32x32.png")
INF = float("inf")
MINUTE = 60
DAY = 86400
HOUR = 3600
SYMBOL = "DCR"

MinSeedBytes = 16 # 128 bits
MaxSeedBytes = 64 # 512 bits