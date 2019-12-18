"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

Just some constants.
"""
import os

PYDECRED_PACKAGEDIR = os.path.dirname(os.path.realpath(__file__))
FAVICON = os.path.join(PYDECRED_PACKAGEDIR, "favicon-32x32.png")
LOGO = os.path.join(PYDECRED_PACKAGEDIR, "logo.svg")
INF = float("inf")
MINUTE = 60
DAY = 86400
HOUR = 3600
SYMBOL = "DCR"

MinSeedBytes = 16  # 128 bits
MaxSeedBytes = 64  # 512 bits
