"""
Copyright (c) 2019, The Decred developers

This example script will prompt for a password and create a password-encrypted
testnet wallet. The mnemonic seed and an address are printed.
"""

import os
from getpass import getpass

from tinydecred import config
from tinydecred.util.helpers import mkdir
from tinydecred.wallet.wallet import Wallet

# Load configuration for testnet
config.load("testnet")

# Create an encrypted, password-protected wallet file.
password = getpass()
mkdir("testnet")
walletPath = os.path.join("testnet", "testnet_wallet.db")
mnemonicSeed, wallet = Wallet.create(walletPath, password)

# Print the seed words and an address.
print("Mnemonic seed\n-------------")
print(" ".join(mnemonicSeed))
print("Receive DCR at %s" % wallet.currentAddress())
