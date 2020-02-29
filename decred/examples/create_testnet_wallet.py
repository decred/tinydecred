"""
Copyright (c) 2019, The Decred developers

This example script will prompt for a password and create a password-encrypted
testnet wallet. The mnemonic seed and an address are printed.
"""

from getpass import getpass

from decred.wallet.simple import SimpleWallet


def main():
    # Create an encrypted, password-protected wallet file.
    password = getpass()
    walletDir = "wallets"
    print("Creating and synchronizing wallet")
    wallet, words = SimpleWallet.create(walletDir, password, "testnet")

    # Print the seed words and an address.
    try:
        print("Mnemonic seed\n-------------")
        print(" ".join(words))
        print("Receive DCR at %s" % wallet.currentAddress())
    finally:
        wallet.close()


if __name__ == "__main__":
    main()
