"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from tinydecred.crypto import crypto
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.pydecred import nets
from tinydecred.util import helpers
from tinydecred.wallet import accounts

testSeed = ByteArray(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
).b


def addressForPubkeyBytes(b, net):
    """
    Helper function to convert ECDSA public key bytes to a human readable
    ripemind160 hash for use on the specified network.

    Args:
        b (bytes): Public key bytes.
        net (object): Network the address will be used on.

    Returns:
        crypto.Address: A pubkey-hash address.
    """
    return crypto.newAddressPubKeyHash(
        crypto.hash160(b), net, crypto.STEcdsaSecp256k1
    ).string()


class TestAccounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up for tests. Arguments are ignored.
        """
        helpers.prepareLogger("TestTinyCrypto")
        # log.setLevel(0)

    def test_child_neuter(self):
        """
        Test the ExtendedKey.neuter method.
        """
        extKey = accounts.newMaster(testSeed, nets.mainnet)
        extKey.child(0)
        pub = extKey.neuter()
        self.assertEqual(
            pub.string(),
            "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbR"
            "qbfTCJ9BUnWPCkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk",
        )

    def test_accounts(self):
        """
        Test account functionality.
        """
        pw = "abc".encode()
        am = accounts.createNewAccountManager(testSeed, bytearray(0), pw, nets.mainnet)
        rekey = am.acctPrivateKey(0, nets.mainnet, pw)
        pubFromPriv = rekey.neuter()
        addr1 = pubFromPriv.deriveChildAddress(5, nets.mainnet)
        pubKey = am.acctPublicKey(0, nets.mainnet, "")
        addr2 = pubKey.deriveChildAddress(5, nets.mainnet)
        self.assertEqual(addr1, addr2)
        acct = am.openAccount(0, pw)
        for n in range(20):
            acct.nextExternalAddress()
        v = 5
        satoshis = int(round(v * 1e8))
        txid = "abcdefghijkl"
        vout = 2
        from tinydecred.pydecred import dcrdata

        utxo = dcrdata.UTXO(
            address=None,
            txid=txid,
            vout=vout,
            scriptPubKey=ByteArray(0),
            amount=v,
            satoshis=satoshis,
            maturity=1,
        )
        utxocount = lambda: len(list(acct.utxoscan()))
        acct.addUTXO(utxo)
        self.assertEqual(utxocount(), 1)
        self.assertEqual(acct.calcBalance(1).total, satoshis)
        self.assertEqual(acct.calcBalance(1).available, satoshis)
        self.assertEqual(acct.calcBalance(0).available, 0)
        self.assertIsNot(acct.getUTXO(txid, vout), None)
        self.assertIs(acct.getUTXO("", -1), None)
        self.assertTrue(acct.caresAboutTxid(txid))
        utxos = acct.UTXOsForTXID(txid)
        self.assertEqual(len(utxos), 1)
        acct.spendUTXOs(utxos)
        self.assertEqual(utxocount(), 0)
        acct.addUTXO(utxo)
        self.assertEqual(utxocount(), 1)
        acct.spendUTXO(utxo)
        self.assertEqual(utxocount(), 0)

    def test_newmaster(self):
        """
        Test extended key derivation.
        """
        kpriv = accounts.newMaster(testSeed, nets.mainnet)
        self.assertEqual(
            kpriv.key.hex(),
            "f2418d00085be520c6449ddb94b25fe28a1944b5604193bd65f299168796f862",
        )
        kpub = kpriv.neuter()
        self.assertEqual(
            kpub.key.hex(),
            "0317a47499fb2ef0ff8dc6133f577cd44a5f3e53d2835ae15359dbe80c41f70c9b",
        )
        kpub_branch0 = kpub.child(0)
        self.assertEqual(
            kpub_branch0.key.hex(),
            "02dfed559fddafdb8f0041cdd25c4f9576f71b0e504ce61837421c8713f74fb33c",
        )
        kpub_branch0_child1 = kpub_branch0.child(1)
        self.assertEqual(
            kpub_branch0_child1.key.hex(),
            "03745417792d529c66980afe36f364bee6f85a967bae117bc4d316b77e7325f50c",
        )
        kpriv_branch0 = kpriv.child(0)
        self.assertEqual(
            kpriv_branch0.key.hex(),
            "6469a8eb3ed6611cc9ee4019d44ec545f3174f756cc41f9867500efdda742dd9",
        )
        kpriv_branch0_child1 = kpriv_branch0.child(1)
        self.assertEqual(
            kpriv_branch0_child1.key.hex(),
            "fb8efe52b3e4f31bc12916cbcbfc0e84ef5ebfbceb7197b8103e8009c3a74328",
        )
        kpriv01_neutered = kpriv_branch0_child1.neuter()
        self.assertEqual(kpriv01_neutered.key.hex(), kpub_branch0_child1.key.hex())

    def test_change_addresses(self):
        """
        Test internal branch address derivation.
        """
        pw = "abc".encode()
        acctManager = accounts.createNewAccountManager(
            testSeed, bytearray(0), pw, nets.mainnet
        )
        # acct = acctManager.account(0)
        acct = acctManager.openAccount(0, pw)
        for i in range(10):
            acct.nextInternalAddress()

    def test_gap_handling(self):
        internalAddrs = [
            "DskHpgbEb6hqkuHchHhtyojpehFToEtjQSo",
            "Dsm4oCLnLraGDedfU5unareezTNT75kPbRb",
            "DsdN6A9bWhKKJ7PAGdcDLxQrYPKEnjnDv2N",
            "Dsifz8eRHvQrfaPXgHHLMDHZopFJq2pBPU9",
            "DsmmzJiTTmpafdt2xx7LGk8ZW8cdAKe53Zx",
            "DsVB47P4N23PK5C1RyaJdqkQDzVuCDKGQbj",
            "DsouVzScdUUswvtCAv6nxRzi2MeufpWnELD",
            "DsSoquT5SiDPfksgnveLv3r524k1v8RamYm",
            "DsbVDrcfhbdLy4YaSmThmWN47xhxT6FC8XB",
            "DsoSrtGYKruQLbvhA92xeJ6eeuAR1GGJVQA",
        ]

        externalAddrs = [
            "DsmP6rBEou9Qr7jaHnFz8jTfrUxngWqrKBw",
            "DseZQKiWhN3ceBwDJEgGhmwKD3fMbwF4ugf",
            "DsVxujP11N72PJ46wgU9sewptWztYUy3L7o",
            "DsYa4UBo379cRMCTpDLxYVfpMvMNBdAGrGS",
            "DsVSEmQozEnsZ9B3D4Xn4H7kEedDyREgc18",
            "DsifDp8p9mRocNj7XNNhGAsYtfWhccc2cry",
            "DsV78j9aF8NBwegbcpPkHYy9cnPM39jWXZm",
            "DsoLa9Rt1L6qAVT9gSNE5F5XSDLGoppMdwC",
            "DsXojqzUTnyRciPDuCFFoKyvQFd6nQMn7Gb",
            "DsWp4nShu8WxefgoPej1rNv4gfwy5AoULfV",
        ]

        accounts.DefaultGapLimit = gapLimit = 5
        pw = "abc".encode()
        am = accounts.createNewAccountManager(testSeed, bytearray(0), pw, nets.mainnet)
        account = am.openAccount(0, pw)
        account.gapLimit = gapLimit
        listsAreEqual = lambda a, b: len(a) == len(b) and all(
            x == y for x, y in zip(a, b)
        )

        self.assertTrue(
            listsAreEqual(account.internalAddresses, internalAddrs[:gapLimit])
        )
        # The external branch starts with the "last seen" at the zeroth address, so
        # has one additional address to start.
        self.assertTrue(
            listsAreEqual(account.externalAddresses, externalAddrs[: gapLimit + 1])
        )

        account.addTxid(internalAddrs[0], "somerandomtxid")
        newAddrs = account.generateGapAddresses()
        self.assertEqual(len(newAddrs), 1)
        self.assertEqual(newAddrs[0], internalAddrs[5])

        # The zeroth external address is considered "seen", so this should not
        # change anything.
        account.addTxid(externalAddrs[0], "somerandomtxid")
        newAddrs = account.generateGapAddresses()
        self.assertEqual(len(newAddrs), 0)

        # Mark the 1st address as seen.
        account.addTxid(externalAddrs[1], "somerandomtxid")
        newAddrs = account.generateGapAddresses()
        self.assertEqual(len(newAddrs), 1)
        self.assertEqual(externalAddrs[1], account.currentAddress())

        # cursor should be at index 0, last seen 1, max index 6, so calling
        # nextExternalAddress 5 time should put the cursor at index 6, which is
        # the gap limit.
        for i in range(5):
            account.nextExternalAddress()
        self.assertEqual(account.currentAddress(), externalAddrs[6])

        # one more should wrap the cursor back to 1, not zero, so the current
        # address is lastSeenExt(=1) + cursor(=1) = 2
        a1 = account.nextExternalAddress()
        self.assertEqual(account.currentAddress(), externalAddrs[2])
        self.assertEqual(a1, account.currentAddress())

        # Sanity check that internal addresses are wrapping too.
        for i in range(20):
            account.nextInternalAddress()
        addrs = account.internalAddresses
        self.assertEqual(addrs[len(addrs) - 1], internalAddrs[5])
