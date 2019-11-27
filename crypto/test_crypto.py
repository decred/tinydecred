"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest
from tinydecred.crypto import crypto
from tinydecred.crypto.bytearray import ByteArray

class TestCrypto(unittest.TestCase):
    def test_encryption(self):
        '''
        Test encryption and decryption.
        '''
        a = crypto.SecretKey("abc".encode())
        aEnc = a.encrypt(b'dprv3n8wmhMhC7p7QuzHn4fYgq2d87hQYAxWH3RJ6pYFrd7LAV71RcBQWrFFmSG3yYWVKrJCbYTBGiniTvKcuuQmi1hA8duKaGM8paYRQNsD1P6')
        b = crypto.SecretKey.rekey("abc".encode(), a.params())
        aUnenc = b.decrypt(aEnc.bytes())
        self.assertTrue(a, aUnenc)
    def test_addr_pubkey(self):
        from tinydecred.pydecred import mainnet
        pairs = [
            ("033b26959b2e1b0d88a050b111eeebcf776a38447f7ae5806b53c9b46e07c267ad", "DkRKjw7LmGCSzBwaUtjQLfb75Zcx9hH8yGNs3qPSwVzZuUKs7iu2e"),
            ("0389ced3eaee84d5f0d0e166f6cd15f1bf6f429d1d13709393b418a6fb22d8be53", "DkRLLaJWkmH75iZGtQYE6FEf16zxeHr6TCAF59tGxhds4MFc2HqUS"),
            ("02a14a0023d7d8cbc5d39fa60f7e4dc4d5bf18a7031f52875fbca6bf837f68713f", "DkM3hdWuKSSTm7Vq8WZx5f294vcZbPkAQYBDswkjmF1CFuWCRYxTr"),
            ("03c3e3d7cde1c453a6283f5802a73d1cb3827cb4b007f58e3a52a36ce189934b6a", "DkRLn9vzsjK4ZYgDKy7JVYHKGvpZU5CYGK9H8zF2VCWbpTyVsEf4P"),
            ("0254e17b230e782e591a9910794fdbf9943d500a47f2bf8446e1238f84e809bffc", "DkM37ymaat9j6oTFii1MZVpXrc4aRLEMHhTZrvrz8QY6BZ2HX843L"),
        ]
        for hexKey, addrStr in pairs:
            addr = crypto.AddressSecpPubKey(ByteArray(hexKey), mainnet)
            self.assertEqual(addr.string(), addrStr)
    def test_addr_pubkey_hash(self):
        from tinydecred.pydecred import mainnet
        pairs = [
            ("e201ee2f37bcc0ba0e93f82322e48333a92b9355", "DsmZvWuokf5NzFwFfJk5cALZZBZivjkhMSQ"),
            ("5643d59202de158b509544d40b32e85bfaf6243e", "DsYq2s8mwpM6vXLbjb8unhNmBXFofPzcrrv"),
            ("c5fa0d15266e055eaf8ec7c4d7a679885266ef0d", "Dsj1iA5PBCU6Nmpe6jqucwfHK17WmSKd3uG"),
            ("73612f7b7b1ed32ff44dded7a2cf87c206fabf8a", "DsbUyd4DueVNyvfh542kZDXNEGKByUAi1RV"),
            ("a616bc09179e31e6d9e3abfcb16ac2d2baf45141", "Dsg76ttvZmTFchZ5mWRnAUg6UGfCyrq86ch"),
        ]
        for pubkeyHash, addrStr in pairs:
            addr = crypto.AddressPubKeyHash(mainnet.PubKeyHashAddrID, ByteArray(pubkeyHash))
            self.assertEqual(addr.string(), addrStr)
    def test_addr_script_hash(self):
        from tinydecred.pydecred import mainnet
        pairs = [
            ("52fdfc072182654f163f5f0f9a621d729566c74d", "Dcf2QjJ1pSnLwthhw1cwE55MVZNQVXDZWQT"),
            ("10037c4d7bbb0407d1e2c64981855ad8681d0d86", "DcYvG3fPxHDZ5pzW8nj4rcYq5kM9XFxXpUy"),
            ("d1e91e00167939cb6694d2c422acd208a0072939", "DcrbVYmhm5yX9mw9qdwUVWw6psUhPGrQJsT"),
            ("487f6999eb9d18a44784045d87f3c67cf22746e9", "Dce4vLzzENaZT7D2Wq5crRZ4VwfYMDMWkD9"),
            ("95af5a25367951baa2ff6cd471c483f15fb90bad", "Dcm73og7Hn9PigaNu59dHgKnNSP1myCQ39t"),
        ]
        for scriptHash, addrStr in pairs:
            addr = crypto.newAddressScriptHashFromHash(ByteArray(scriptHash), mainnet)
            self.assertEqual(addr.string(), addrStr)
