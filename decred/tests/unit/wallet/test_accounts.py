"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import os
from tempfile import TemporaryDirectory

import pytest

from decred import DecredError
from decred.crypto import crypto, rando
from decred.dcr import nets
from decred.util import database, encode
from decred.wallet import accounts


LOGGER_ID = "test_accounts"


testSeed = encode.ByteArray(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
).b

tRoot = crypto.ExtendedKey.new(testSeed)


def test_child_neuter(prepareLogger):
    """
    Test the ExtendedKey.neuter method.
    """
    extKey = crypto.ExtendedKey.new(testSeed)
    extKey.setNetwork(nets.mainnet)
    extKey.child(0)
    pub = extKey.neuter()
    expStr = (
        "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbRqbfTCJ9BUnWP"
        + "CkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk"
    )
    assert pub.string() == expStr


def test_change_addresses(prepareLogger):
    """
    Test internal branch address derivation.
    """
    cryptoKey = encode.ByteArray(rando.generateSeed(32))
    with TemporaryDirectory() as tempDir:
        db = database.KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
        # ticker for coin type is ok. Case insensitive.
        am = accounts.createNewAccountManager(tRoot, cryptoKey, "DcR", nets.mainnet, db)
        acct = am.openAccount(0, cryptoKey)
        for i in range(10):
            acct.nextInternalAddress()


def test_account_manager(prepareLogger):
    cryptoKey = encode.ByteArray(rando.generateSeed(32))
    with TemporaryDirectory() as tempDir:
        db = database.KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
        # 42 = Decred
        am = accounts.createNewAccountManager(tRoot, cryptoKey, 42, nets.mainnet, db)

        acct = am.openAccount(0, cryptoKey)
        tempAcct = am.addAccount(cryptoKey, "temp")
        assert am.account(1) == tempAcct
        assert am.listAccounts() == [acct, tempAcct]
        am.accounts[3] = tempAcct
        del am.accounts[1]
        with pytest.raises(AssertionError):
            am.listAccounts()
        del am.accounts[3]

        with pytest.raises(DecredError):
            accounts.AccountManager.unblob(encode.BuildyBytes(0))

        zeroth = acct.currentAddress()
        b = am.serialize()
        reAM = accounts.AccountManager.unblob(b.b)

        assert am.coinType == reAM.coinType
        assert am.netName == reAM.netName
        assert am.netName == reAM.netName

        reAM.load(db, None)
        reAcct = reAM.openAccount(0, cryptoKey)
        reZeroth = reAcct.currentAddress()

        assert zeroth == reZeroth
