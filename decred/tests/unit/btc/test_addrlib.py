"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

from base58 import b58decode
import bech32
import pytest

from decred import DecredError
from decred.crypto import crypto
from decred.crypto.secp256k1.curve import PrivateKey
from decred.btc import addrlib
from decred.btc.nets import mainnet, testnet
from decred.dcr.nets import mainnet as foreignNet
from decred.util.encode import ByteArray

foreignNet.Bech32HRPSegwit = "foreign"


def test_addresses():
    addrPKH = addrlib.AddressPubKeyHash
    addrSH = addrlib.AddressScriptHash.fromScript
    addrSHH = addrlib.AddressScriptHash
    addrPK = addrlib.AddressPubKey

    addrPKH_w = addrlib.AddressWitnessPubKeyHash
    addrSHH_w = addrlib.AddressWitnessScriptHash
    # addrSHH_w = addrlib.AddressWitnessScriptHash

    """
    name (str): A name for the test.
    addr (str): The expected Address.string().
    saddr (str): The expected Address.scriptAddress() after decoding.
    encoded (str): The expected Address.address().
    valid (bool): False if the make func is expected to raise an error.
    scriptAddress (ByteArray): The expected Address.scriptAddress(), but for
        the address made with make.
    make (func -> str): A function to create a new Address.
    netParams (module): The network parameters.
    skipComp (bool): Skip string comparison of decoded address. For
        AddressSecpPubKey, the encoded pubkey is unrecoverable from the
        AddressSecpPubKey.address() string.
    """
    tests = [
        # Positive P2PKH tests.
        dict(
            name="mainnet p2pkh",
            addr="1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX",
            encoded="1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX",
            valid=True,
            scriptAddress=ByteArray("e34cce70c86373273efcc54ce7d2a491bb4a0e84"),
            make=lambda: addrPKH(ByteArray("e34cce70c86373273efcc54ce7d2a491bb4a0e84"), mainnet),
            netParams=mainnet,
        ),
        dict(
            name="mainnet p2pkh 2",
            addr="12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG",
            encoded="12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG",
            valid=True,
            scriptAddress=ByteArray("0ef030107fd26e0b6bf40512bca2ceb1dd80adaa"),
            make=lambda: addrPKH(ByteArray("0ef030107fd26e0b6bf40512bca2ceb1dd80adaa"), mainnet),
            netParams=mainnet,
        ),
        # dict(
        #     name="decred mainnet p2pkh",
        #     addr="DsdvnzfMVZUPeD7HVy6rBbrZcJH6M2qfT8x",
        #     encoded="DsdvnzfMVZUPeD7HVy6rBbrZcJH6M2qfT8x",
        #     valid=True,
        #     scriptAddress=ByteArray("13c60d8e68d7349f5b4ca362c3954b15045061b1"),
        #     make=lambda: addrPKH(ByteArray("13c60d8e68d7349f5b4ca362c3954b15045061b1"), foreignNet),
        #     netParams=foreignNet,
        # ),
        dict(
            name="testnet p2pkh",
            addr="mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
            encoded="mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
            valid=True,
            scriptAddress=ByteArray("78b316a08647d5b77283e512d3603f1f1c8de68f"),
            make=lambda: addrPKH(ByteArray("78b316a08647d5b77283e512d3603f1f1c8de68f"), testnet),
            netParams=testnet,
        ),

        # Negative P2PKH tests.
        dict(
            name="p2pkh wrong hash length",
            addr="",
            valid=False,
            make=lambda: addrPKH(ByteArray("000ef030107fd26e0b6bf40512bca2ceb1dd80adaa"), mainnet),
            netParams=mainnet,
        ),
        dict(
            name="p2pkh bad checksum",
            addr="1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gY",
            valid=False,
            netParams=mainnet,
        ),

        # Positive P2SH tests.
        dict(
            # Taken from transactions:
            # output: 3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac
            # input:  837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba.
            name="mainnet p2sh",
            addr="3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
            encoded="3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
            valid=True,
            scriptAddress=ByteArray("f815b036d9bbbce5e9f2a00abd1bf3dc91e95510"),
            make=lambda: addrSH(
                ByteArray(
                    "52410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235"
                    "d6126b1d8334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f87"
                    "22084861c5c3291ccffef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fa"
                    "d6edbfb1e754e35fa1c7844c41f322a1863d4621353ae"
                ),
                mainnet,
            ),
            netParams=mainnet,
        ),
        # script: 512102fcc6070080d2e44f7b9a280c744ca09a658ce05b87a4d81dd9dd2446b6953f1a21027b3226787328bb53659290a44bd33acc0d3a79c64b62722fb39f58bb211cb0d452ae
        # dict(
        #     name="decred mainnet P2SH ",
        #     addr="DcaephHCqjdfb3gPz778DJZWvwmUUs3ssGk",
        #     encoded="DcaephHCqjdfb3gPz778DJZWvwmUUs3ssGk",
        #     valid=True,
        #     scriptAddress=ByteArray("e9c02720843a9b8e49dea2981f0f14d8247be48f"),
        #     make=lambda: addrSHH(ByteArray("e9c02720843a9b8e49dea2981f0f14d8247be48f"), foreignNet),
        #     netParams=foreignNet,
        # ),
        dict(
            # Taken from transactions:
            # output: b0539a45de13b3e0403909b8bd1a555b8cbe45fd4e3f3fda76f3a5f52835c29d
            # input: (not yet redeemed at time test was written)
            name="mainnet p2sh 2",
            addr="3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8",
            encoded="3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8",
            valid=True,
            # result=btcutil.TstAddressScriptHash(
            #     ByteArray(
            #         "e8c300c87986efa84c37c0519929019ef86eb5b4"},
            #     mainnet.ScriptHashAddrID),
            scriptAddress=ByteArray("e8c300c87986efa84c37c0519929019ef86eb5b4"),
            make=lambda: addrSHH(ByteArray("e8c300c87986efa84c37c0519929019ef86eb5b4"), mainnet),
            netParams=mainnet,
        ),
        dict(
            # Taken from bitcoind base58_keys_valid.
            name="testnet p2sh",
            addr="2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
            encoded="2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
            valid=True,
            # result=btcutil.TstAddressScriptHash(
            #     ByteArray(
            #         "c579342c2c4c9220205e2cdc285617040c924a0a"},
            #     chaincfg.TestNet3Params.ScriptHashAddrID),
            scriptAddress=ByteArray("c579342c2c4c9220205e2cdc285617040c924a0a"),
            make=lambda: addrSHH(ByteArray("c579342c2c4c9220205e2cdc285617040c924a0a"), testnet),
            netParams=testnet,
        ),

        # # Negative P2SH tests.
        dict(
            name="p2sh wrong hash length",
            addr="",
            valid=False,
            make=lambda: addrSHH(ByteArray("00f815b036d9bbbce5e9f2a00abd1bf3dc91e95510"), mainnet),
            netParams=mainnet,
        ),

        # Positive P2PK tests.
        dict(
            name="mainnet p2pk compressed (02)",
            addr="02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4",
            encoded="13CG6SJ3yHUXo4Cr2RY4THLLJrNFuG3gUg",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"},
            #     btcutil.PKFCompressed, mainnet.PubKeyHashAddrID),
            scriptAddress=ByteArray("02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"),
            make=lambda: addrPK(ByteArray("02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"), mainnet),
            netParams=mainnet,
        ),
        dict(
            name="mainnet p2pk compressed (03)",
            addr="03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65",
            encoded="15sHANNUBSh6nDp8XkDPmQcW6n3EFwmvE6",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"},
            #     btcutil.PKFCompressed, mainnet.PubKeyHashAddrID),
            scriptAddress=ByteArray("03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"),
            make=lambda: addrPK(ByteArray("03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"), mainnet),
            netParams=mainnet,
        ),
        dict(
            name="mainnet p2pk uncompressed (04)",
            addr="0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2" +
                 "e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
            encoded="12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"},
            #     btcutil.PKFUncompressed, mainnet.PubKeyHashAddrID),
            scriptAddress=ByteArray("0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"),
            make=lambda: addrPK(
                ByteArray("0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"),
                mainnet,
            ),
            netParams=mainnet,
        ),
        dict(
            name="mainnet p2pk hybrid (06)",
            addr="06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4" +
                 "0d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e",
            encoded="1Ja5rs7XBZnK88EuLVcFqYGMEbBitzchmX",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e"},
            #     btcutil.PKFHybrid, mainnet.PubKeyHashAddrID),
            scriptAddress=ByteArray("06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e"),
            make=lambda: addrPK(
                ByteArray("06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e"),
                mainnet,
            ),
            netParams=mainnet,
        ),
        dict(
            name="mainnet p2pk hybrid (07)",
            addr="07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65" +
                 "37a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b",
            encoded="1ExqMmf6yMxcBMzHjbj41wbqYuqoX6uBLG",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b"},
            #     btcutil.PKFHybrid, mainnet.PubKeyHashAddrID),
            scriptAddress=ByteArray("07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b"),
            make=lambda: addrPK(
                ByteArray("07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b"),
                mainnet,
            ),
            netParams=mainnet,
        ),
        dict(
            name="testnet p2pk compressed (02)",
            addr="02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4",
            encoded="mhiDPVP2nJunaAgTjzWSHCYfAqxxrxzjmo",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"},
            #     btcutil.PKFCompressed, chaincfg.TestNet3Params.PubKeyHashAddrID),
            scriptAddress=ByteArray("02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"),
            make=lambda: addrPK(ByteArray("02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"), testnet),
            netParams=testnet,
        ),
        dict(
            name="testnet p2pk compressed (03)",
            addr="03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65",
            encoded="mkPETRTSzU8MZLHkFKBmbKppxmdw9qT42t",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"},
            #     btcutil.PKFCompressed, chaincfg.TestNet3Params.PubKeyHashAddrID),
            scriptAddress=ByteArray("03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"),
            make=lambda: addrPK(ByteArray("03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"), testnet),
            netParams=testnet,
        ),
        dict(
            name="testnet p2pk uncompressed (04)",
            addr="0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5" +
                 "cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
            encoded="mh8YhPYEAYs3E7EVyKtB5xrcfMExkkdEMF",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"},
            #     btcutil.PKFUncompressed, chaincfg.TestNet3Params.PubKeyHashAddrID),
            scriptAddress=ByteArray("0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"),
            make=lambda: addrPK(
                ByteArray("0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"),
                testnet,
            ),
            netParams=testnet,
        ),
        dict(
            name="testnet p2pk hybrid (06)",
            addr="06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b" +
                 "40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e",
            encoded="my639vCVzbDZuEiX44adfTUg6anRomZLEP",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e"},
            #     btcutil.PKFHybrid, chaincfg.TestNet3Params.PubKeyHashAddrID),
            scriptAddress=ByteArray("06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e"),
            make=lambda: addrPK(
                ByteArray("06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e"),
                testnet,
            ),
            netParams=testnet,
        ),
        dict(
            name="testnet p2pk hybrid (07)",
            addr="07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6" +
                 "537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b",
            encoded="muUnepk5nPPrxUTuTAhRqrpAQuSWS5fVii",
            valid=True,
            # result=btcutil.TstAddressPubKey(
            #     ByteArray(
            #         "07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b"},
            #     btcutil.PKFHybrid, chaincfg.TestNet3Params.PubKeyHashAddrID),
            scriptAddress=ByteArray("07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b"),
            make=lambda: addrPK(
                ByteArray("07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b"),
                testnet,
            ),
            netParams=testnet,
        ),

        # Segwit address tests.
        dict(
            name="segwit mainnet p2wpkh v0",
            # addr was capitalized in the btcutil tests. I didn't feel that was important.
            addr="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            encoded="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            valid=True,
            # result=btcutil.TstAddressWitnessPubKeyHash(
            #     0,
            #     [20]byte{
            #         "751e76e8199196d454941c45d1b3a323f1433bd6"},
            #     mainnet.Bech32HRPSegwit),
            scriptAddress=ByteArray("751e76e8199196d454941c45d1b3a323f1433bd6"),
            make=lambda: addrPKH_w(ByteArray("751e76e8199196d454941c45d1b3a323f1433bd6"), mainnet),
            netParams=mainnet,
        ),
        dict(
            name="segwit mainnet p2wsh v0",
            addr="bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            encoded="bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            valid=True,
            # result=btcutil.TstAddressWitnessScriptHash(
            #     0,
            #     [32]byte{
            #         "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
            #     mainnet.Bech32HRPSegwit),
            scriptAddress=ByteArray("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            make=lambda: addrSHH_w(ByteArray("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), mainnet),
            netParams=mainnet,
        ),
        dict(
            name="segwit testnet p2wpkh v0",
            addr="tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            encoded="tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            valid=True,
            # result=btcutil.TstAddressWitnessPubKeyHash(
            #     0,
            #     [20]byte{
            #         "751e76e8199196d454941c45d1b3a323f1433bd6"},
            #     chaincfg.TestNet3Params.Bech32HRPSegwit),
            scriptAddress=ByteArray("751e76e8199196d454941c45d1b3a323f1433bd6"),
            make=lambda:addrPKH_w(ByteArray("751e76e8199196d454941c45d1b3a323f1433bd6"), testnet),
            netParams=testnet,
        ),
        dict(
            name="segwit testnet p2wsh v0",
            addr="tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            encoded="tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            valid=True,
            # result=btcutil.TstAddressWitnessScriptHash(
            #     0,
            #     [32]byte{
            #         "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
            #     chaincfg.TestNet3Params.Bech32HRPSegwit),
            scriptAddress=ByteArray("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            make=lambda: addrSHH_w(ByteArray("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), testnet),
            netParams=testnet,
        ),
        dict(
            name="segwit testnet p2wsh witness v0",
            addr="tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            encoded="tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            valid=True,
            # result=btcutil.TstAddressWitnessScriptHash(
            #     0,
            #     [32]byte{
            #         "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
            #     chaincfg.TestNet3Params.Bech32HRPSegwit),
            scriptAddress=ByteArray("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            make=lambda: addrSHH_w(ByteArray("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"), testnet),
            netParams=testnet,
        ),
        # dict(
        #     name="segwit litecoin mainnet p2wpkh v0",
        #     addr="LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KGMN4N9",
        #     encoded="ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
        #     valid=True,
        #     # result=btcutil.TstAddressWitnessPubKeyHash(
        #     #     0,
        #     #     [20]byte{
        #     #         "751e76e8199196d454941c45d1b3a323f1433bd6"},
        #     #     CustomParams.Bech32HRPSegwit,
        #     # ),
        #     scriptAddress=ByteArray("751e76e8199196d454941c45d1b3a323f1433bd6"),
        #     make=lambda: addrPKH_w(ByteArray("751e76e8199196d454941c45d1b3a323f1433bd6"), foreignNet),
        #     netParams=foreignNet,
        # ),
        # # Unsupported witness versions (version 0 only supported at this point)
        dict(
            name="segwit mainnet witness v1",
            addr="bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            valid=False,
            netParams=mainnet,
        ),
        dict(
            name="segwit mainnet witness v16",
            addr="BC1SW50QA3JX3S",
            valid=False,
            netParams=mainnet,
        ),
        dict(
            name="segwit mainnet witness v2",
            addr="bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
            valid=False,
            netParams=mainnet,
        ),
        # Invalid segwit addresses
        dict(
            name="segwit invalid hrp",
            addr="tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            valid=False,
            netParams=testnet,
        ),
        dict(
            name="segwit invalid checksum",
            addr="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            valid=False,
            netParams=mainnet,
        ),
        dict(
            name="segwit invalid witness version",
            addr="BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            valid=False,
            netParams=mainnet,
        ),
        dict(
            name="segwit invalid program length",
            addr="bc1rw5uspcuh",
            valid=False,
            netParams=mainnet,
        ),
        dict(
            name="segwit invalid program length",
            addr="bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            valid=False,
            netParams=mainnet,
        ),
        dict(
            name="segwit invalid program length for witness version 0 (per BIP141)",
            addr="BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            valid=False,
            netParams=mainnet,
        ),
        dict(
            name="segwit mixed case",
            addr="tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            valid=False,
            netParams=testnet,
        ),
        dict(
            name="segwit zero padding of more than 4 bits",
            addr="tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
            valid=False,
            netParams=testnet,
        ),
        dict(
            name="segwit non-zero padding in 8-to-5 conversion",
            addr="tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            valid=False,
            netParams=testnet,
        ),
    ]

    for test in tests:
        # Decode addr and compare error against valid.
        err = None
        name = test.get("name")
        try:
            decoded = addrlib.decodeAddress(test["addr"], test["netParams"])
        except (DecredError, ValueError) as e:
            err = e
        assert (err is None) == test["valid"], f"{name} error: {err}"

        if err is None:
            # Ensure the stringer returns the same address as the original.
            assert test["addr"] == decoded.string(), name

            # Encode again and compare against the original.
            encoded = decoded.encodeAddress()
            assert test["encoded"] == encoded

            # Perform type-specific calculations.
            if isinstance(decoded, addrlib.AddressPubKeyHash):
                d = ByteArray(b58decode(encoded))
                saddr = d[1: 1 + crypto.RIPEMD160_SIZE]

            elif isinstance(decoded, addrlib.AddressScriptHash):
                d = ByteArray(b58decode(encoded))
                saddr = d[1: 1 + crypto.RIPEMD160_SIZE]

            elif isinstance(decoded, addrlib.AddressPubKey):
                # Ignore the error here since the script
                # address is checked below.
                try:
                    saddr = ByteArray(decoded.string())
                except ValueError:
                    saddr = test["saddr"]

            elif isinstance(decoded, addrlib.AddressWitnessPubKeyHash):
                _, addrb = bech32.decode(test["netParams"].Bech32HRPSegwit, encoded)
                saddr = ByteArray(addrb)

            elif isinstance(decoded, addrlib.AddressWitnessScriptHash):
                _, addrb = bech32.decode(test["netParams"].Bech32HRPSegwit, encoded)
                saddr = ByteArray(addrb)

            else:
                raise AssertionError(
                    f"Decoded address is of unknown type {type(decoded)}"
                )

            # Check script address, as well as the Hash160 method for P2PKH and
            # P2SH addresses.
            assert saddr == decoded.scriptAddress(), name

            if isinstance(decoded, addrlib.AddressPubKeyHash):
                assert decoded.pkHash == saddr

            if isinstance(decoded, addrlib.AddressScriptHash):
                assert decoded.hash160() == saddr

        make = test.get("make")
        if not test["valid"]:
            # If address is invalid, but a creation function exists,
            # verify that it raises a DecredError.
            if make:
                try:
                    make()
                    raise AssertionError("invalid tests should raise exception")
                except DecredError:
                    pass
            continue

        # Valid test, compare address created with f against expected result.
        addr = make()
        assert addr != object()
        if not test.get("skipComp"):
            assert decoded == addr, name
            assert decoded == addr.string(), name
            assert addr.string() == decoded, name
        assert addr.scriptAddress() == test["scriptAddress"], name

        # Test blobbing
        b = addrlib.Address.blob(addr)
        reAddr = addrlib.Address.unblob(b)
        assert addr == reAddr


def test_EncodeDecodeWIF():
    validEncodeCases = [
        dict(
            privateKey=ByteArray("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"),
            net=mainnet,
            compress=False,
            wif="5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            publicKey=ByteArray("04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a"),
            name="encodeValidUncompressedMainNetWif",
        ),
        dict(
            privateKey=ByteArray("dda35a1488fb97b6eb3fe6e9ef2a25814e396fb5dc295fe994b96789b21a0398"),
            net=testnet,
            compress=True,
            wif="cV1Y7ARUr9Yx7BR55nTdnR7ZXNJphZtCCMBTEZBJe1hXt2kB684q",
            publicKey=ByteArray("02eec2540661b0c39d271570742413bd02932dd0093493fd0beced0b7f93addec4"),
            name="encodeValidCompressedTestNet3Wif",
        ),
    ]

    for validCase in validEncodeCases:
        priv = PrivateKey.fromBytes(validCase["privateKey"])
        wif = addrlib.WIF(privKey=priv, compressPubKey=validCase["compress"], netID=validCase["net"])

        assert wif.isForNet(validCase["net"])

        assert wif.serializePubKey() == validCase["publicKey"]

        encWIF = wif.string()
        assert encWIF == validCase["wif"]

        assert addrlib.WIF.decode(encWIF).string() == validCase["wif"]

    invalidDecodeCases = [
        # name string
        # wif  string
        # err  error
        dict(
            name="decodeInvalidLengthWif",
            wif="deadbeef",
        ),
        dict(
            name="decodeInvalidCompressMagicWif",
            wif="KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sfZr2ym",
        ),
        dict(
            name="decodeInvalidChecksumWif",
            wif="5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTj",
        ),
    ]

    for invalidCase in invalidDecodeCases:
        with pytest.raises(DecredError):
            addrlib.WIF.decode(invalidCase["wif"])
