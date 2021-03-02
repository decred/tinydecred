"""
Copyright (c) 2020, The Decred developers
"""

from decred.decred.dcr import nets
from decred.decred.wallet.wallet import SimpleWallet, Wallet


PASSWORD = "test_password"
NET_NAME = "testnet"

# Testnet return address for faucet.decred.org.
TESTNET_ADDRESS = "TsfDLrRkk9ciUuwfp2b8PawwnukYD7yAjGd"


def test_SimpleWallet(tmp_path):
    wallet, _ = SimpleWallet.create(tmp_path, PASSWORD, NET_NAME)
    wallet.close()
    wallet = SimpleWallet(tmp_path, PASSWORD, NET_NAME)
    wallet.close()


def test_Wallet(tmp_path):
    first_wallet_path = tmp_path / "first_wallet"
    netParams = nets.parse(NET_NAME)
    words, _ = Wallet.create(first_wallet_path, PASSWORD, netParams)
    second_wallet_path = tmp_path / "second_wallet"
    Wallet.createFromMnemonic(words, second_wallet_path, PASSWORD, netParams)
