"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, the Decred developers
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
WALLET_CONNECTED = "wallet_connected"
PURCHASEINFO_SIGNAL = "purchaseinfo_signal"
SPENT_TICKETS_SIGNAL = "spent_tickets_signal"
