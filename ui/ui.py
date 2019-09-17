"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details
"""
import os

PACKAGEDIR = os.path.dirname(os.path.realpath(__file__))
FONTDIR = os.path.join(PACKAGEDIR, "fonts")

TINY = "tiny"
SMALL = "small"
MEDIUM = "medium"
LARGE = "large"

BALANCE_SIGNAL = "balance_signal"
SYNC_SIGNAL = "sync_signal"
WORKING_SIGNAL = "working_signal"
DONE_SIGNAL = "done_signal"
BLOCKCHAIN_CONNECTED = "blockchain_connected"