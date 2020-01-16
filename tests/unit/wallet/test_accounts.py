"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os
from tempfile import TemporaryDirectory
import unittest

from tinydecred.crypto import crypto, rando
from tinydecred.dcr import nets
from tinydecred.util import chains, database, helpers
from tinydecred.util.encode import ByteArray
from tinydecred.wallet import accounts


testSeed = ByteArray(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
).b

tRoot = crypto.ExtendedKey.new(testSeed)


class TestAccounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up for tests. Arguments are ignored.
        """
        helpers.prepareLogger("TACCT")
        chains.registerChain("dcr", None)
        # log.setLevel(0)

    def test_child_neuter(self):
        """
        Test the ExtendedKey.neuter method.
        """
        extKey = crypto.ExtendedKey.new(testSeed)
        extKey.setNetwork(nets.mainnet)
        extKey.child(0)
        pub = extKey.neuter()
        self.assertEqual(
            pub.string(),
            "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbR"
            "qbfTCJ9BUnWPCkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk",
        )

    def test_change_addresses(self):
        """
        Test internal branch address derivation.
        """
        cryptoKey = crypto.ByteArray(rando.generateSeed(32))
        with TemporaryDirectory() as tempDir:
            db = database.KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
            # ticker for coin type is ok. Case insensitive.
            am = accounts.createNewAccountManager(
                tRoot, cryptoKey, "DcR", nets.mainnet, db
            )
            acct = am.openAccount(0, cryptoKey)
            for i in range(10):
                acct.nextInternalAddress()

    def test_account_manager(self):
        cryptoKey = crypto.ByteArray(rando.generateSeed(32))
        with TemporaryDirectory() as tempDir:
            db = database.KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
            # 42 = Decred
            am = accounts.createNewAccountManager(
                tRoot, cryptoKey, 42, nets.mainnet, db
            )

            acct = am.openAccount(0, cryptoKey)
            zeroth = acct.currentAddress()

            b = am.serialize()
            reAM = accounts.AccountManager.unblob(b.b)

            self.assertEqual(am.coinType, reAM.coinType)
            self.assertEqual(am.coinKeyEnc, reAM.coinKeyEnc)
            self.assertEqual(am.netName, reAM.netName)

            reAM.load(db, None)
            reAcct = reAM.openAccount(0, cryptoKey)
            reZeroth = reAcct.currentAddress()

            self.assertEqual(zeroth, reZeroth)
