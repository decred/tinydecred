"""
Copyright (c) 2019, The Decred developers

This example script will prompt for a password and create a password-encrypted
testnet wallet. The mnemonic seed and an address are printed.
"""

import os
from getpass import getpass

from tinydecred import config

# Set the configuration for testnet before loading TD modules.
config.load("testnet")
from tinydecred.util.helpers import mkdir
from tinydecred.wallet.wallet import Wallet


# Create an encrypted, password-protected wallet file.
password = getpass()
mkdir("testnet")
walletPath = os.path.join("testnet", "testnet_wallet.db")
mnemonicSeed, wallet = Wallet.create(walletPath, password)
# Open the zeroth Decred account to get an address.
wallet.open("dcr", 0, password, None)

# Print the seed words and an address.
print("Mnemonic seed\n-------------")
print(" ".join(mnemonicSeed))
print("Receive DCR at %s" % wallet.currentAddress())
