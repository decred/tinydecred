"""
Copyright (c) 2019, The Decred developers

This example script will send 1 DCR from a wallet as created with the
create_testnet_wallet.py example script to the return address from the testnet
faucet at https://faucet.decred.org/.
Before running this script, send the wallet some DCR from the faucet.
"""

from getpass import getpass

from decred.wallet.simple import SimpleWallet

# Testnet return address for faucet.decred.org.
TESTNET_ADDRESS = "TsfDLrRkk9ciUuwfp2b8PawwnukYD7yAjGd"


def main():
    value = int(1 * 1e8)  # 1 DCR, atoms
    password = getpass()
    walletDir = "wallets"
    try:
        print("Opening and synchronizing wallet")
        wallet = SimpleWallet(walletDir, password, "testnet")
    except Exception as e:
        print("Failed to open wallet with provided password: %s" % e)
        exit()

    try:
        # Send some DCR.
        tx = wallet.sendToAddress(value, TESTNET_ADDRESS)
        # Print the transaction ID and a dcrdata link.
        print("Transaction ID: %s" % tx.id())
        print("See transaction at https://testnet.dcrdata.org/tx/%s" % tx.id())
    except Exception as e:
        print("Failed to send transaction: %s" % e)
    finally:
        wallet.close()


if __name__ == "__main__":
    main()
