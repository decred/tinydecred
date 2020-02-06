"""
Copyright (c) 2019, The Decred developers

This example script will send 1 DCR from a wallet as created with the
create_testnet_wallet.py example script to the return address from the testnet
faucet at https://faucet.decred.org/.
Before running this script, send the wallet some DCR from the faucet.
"""

import os
from getpass import getpass

from decred import config

# Set the configuration for testnet before loading decred modules.
config.load("testnet")

from decred.dcr.dcrdata import DcrdataBlockchain
from decred.dcr.nets import testnet
from decred.wallet.wallet import Wallet


# We need a class that implements the Signals API.
class Signals(object):
    def balance(self, bal):
        print(bal)


# DcrdataBlockchain implements a Blockchain API (see api.py) for Decred.
dbPath = os.path.join("testnet", "dcr_testnet.db")
dcrdata = "https://testnet.dcrdata.org"
blockchain = DcrdataBlockchain(dbPath, testnet, dcrdata)

recipient = "TsfDLrRkk9ciUuwfp2b8PawwnukYD7yAjGd"  # testnet return address
value = int(1 * 1e8)  # 1 DCR, atoms
acct = 0  # Every wallet has a zeroth Decred account

# Load the wallet from file.
password = getpass()
walletPath = os.path.join("testnet", "testnet_wallet.db")
try:
    wallet = Wallet.openFile(walletPath, password, Signals())
except Exception as e:
    print("Failed to open wallet with provided password: %s" % e)
    exit()

try:
    # Sync the wallet
    wallet.sync()
    # Send some DCR.
    tx = wallet.openAccount.sendToAddress(value, recipient)
    # Print the transaction ID and a dcrdata link.
    print("transaction ID: %s" % tx.id())
    print("see transaction at https://testnet.dcrdata.org/tx/%s" % tx.id())
except Exception as e:
    print("Failed to send transaction: %s" % e)

blockchain.close()
