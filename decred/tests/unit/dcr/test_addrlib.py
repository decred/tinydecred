"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

from base58 import b58decode

from decred import DecredError
from decred.crypto import crypto
from decred.dcr import addrlib
from decred.dcr.nets import mainnet, testnet
from decred.util.encode import ByteArray


def test_addresses():
    class test:
        def __init__(
            self,
            name="",
            addr="",
            saddr="",
            encoded="",
            valid=False,
            scriptAddress=None,
            f=None,
            net=None,
            skipComp=False,
        ):
            self.name = name
            self.addr = addr
            self.saddr = saddr
            self.encoded = encoded
            self.valid = valid
            self.scriptAddress = scriptAddress
            self.f = f
            self.net = net
            # Pubkey addresses are often printed as pkh addresses, making
            # comparison of the decoded address impossible.
            self.skipComp = skipComp

    addrPKH = addrlib.AddressPubKeyHash
    addrSH = addrlib.AddressScriptHash.fromScript
    addrSHH = addrlib.AddressScriptHash
    addrPK = addrlib.AddressSecpPubKey

    tests = []
    # Positive P2PKH tests.
    tests.append(
        test(
            name="mainnet p2pkh",
            addr="DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
            encoded="DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
            valid=True,
            scriptAddress=ByteArray("2789d58cfa0957d206f025c2af056fc8a77cebb0"),
            f=lambda: addrPKH(
                ByteArray("2789d58cfa0957d206f025c2af056fc8a77cebb0"),
                mainnet,
                crypto.STEcdsaSecp256k1,
            ),
            net=mainnet,
        )
    )
    tests.append(
        test(
            name="mainnet p2pkh 2",
            addr="DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9",
            encoded="DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9",
            valid=True,
            scriptAddress=ByteArray("229ebac30efd6a69eec9c1a48e048b7c975c25f2"),
            f=lambda: addrPKH(
                ByteArray("229ebac30efd6a69eec9c1a48e048b7c975c25f2"),
                mainnet,
                crypto.STEcdsaSecp256k1,
            ),
            net=mainnet,
        )
    )
    tests.append(
        test(
            name="testnet p2pkh",
            addr="Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h",
            encoded="Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h",
            valid=True,
            scriptAddress=ByteArray("f15da1cb8d1bcb162c6ab446c95757a6e791c916"),
            f=lambda: addrPKH(
                ByteArray("f15da1cb8d1bcb162c6ab446c95757a6e791c916"),
                testnet,
                crypto.STEcdsaSecp256k1,
            ),
            net=testnet,
        )
    )

    # Negative P2PKH tests.
    tests.append(
        test(
            name="p2pkh wrong hash length",
            addr="",
            valid=False,
            f=lambda: addrPKH(
                ByteArray("000ef030107fd26e0b6bf40512bca2ceb1dd80adaa"),
                mainnet,
                crypto.STEcdsaSecp256k1,
            ),
        )
    )
    tests.append(
        test(
            name="p2pkh bad checksum",
            addr="TsmWaPM77WSyA3aiQ2Q1KnwGDVWvEkhip23",
            valid=False,
            net=testnet,
        )
    )

    # Positive P2SH tests.
    tests.append(
        test(
            # Taken from transactions:
            # output:
            #   3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac
            # input:
            #   837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba.
            name="mainnet p2sh",
            addr="DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
            encoded="DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
            valid=True,
            scriptAddress=ByteArray("f0b4e85100aee1a996f22915eb3c3f764d53779a"),
            f=lambda: addrSH(
                ByteArray(
                    "512103aa43f0a6c15730d886cc1f0342046d2"
                    "0175483d90d7ccb657f90c489111d794c51ae"
                ),
                mainnet,
            ),
            net=mainnet,
        )
    )
    tests.append(
        test(
            # Taken from transactions:
            # output:
            #   b0539a45de13b3e0403909b8bd1a555b8cbe45fd4e3f3fda76f3a5f52835c29d
            # input: (not yet redeemed at time test was written)
            name="mainnet p2sh 2",
            addr="DcqgK4N4Ccucu2Sq4VDAdu4wH4LASLhzLVp",
            encoded="DcqgK4N4Ccucu2Sq4VDAdu4wH4LASLhzLVp",
            valid=True,
            scriptAddress=ByteArray("c7da5095683436f4435fc4e7163dcafda1a2d007"),
            f=lambda: addrSHH(
                ByteArray("c7da5095683436f4435fc4e7163dcafda1a2d007"), mainnet,
            ),
            net=mainnet,
        )
    )
    tests.append(
        test(
            # Taken from bitcoind base58_keys_valid.
            name="testnet p2sh",
            addr="TccWLgcquqvwrfBocq5mcK5kBiyw8MvyvCi",
            encoded="TccWLgcquqvwrfBocq5mcK5kBiyw8MvyvCi",
            valid=True,
            scriptAddress=ByteArray("36c1ca10a8a6a4b5d4204ac970853979903aa284"),
            f=lambda: addrSHH(
                ByteArray("36c1ca10a8a6a4b5d4204ac970853979903aa284"), testnet,
            ),
            net=testnet,
        )
    )

    # Negative P2SH tests.
    tests.append(
        test(
            name="p2sh wrong hash length",
            addr="",
            valid=False,
            f=lambda: addrSHH(
                ByteArray("00f815b036d9bbbce5e9f2a00abd1bf3dc91e95510"), mainnet,
            ),
            net=mainnet,
        )
    )

    # Positive P2PK tests.
    tests.append(
        test(
            name="mainnet p2pk compressed (0x02)",
            addr="DsT4FDqBKYG1Xr8aGrT1rKP3kiv6TZ5K5th",
            encoded="DsT4FDqBKYG1Xr8aGrT1rKP3kiv6TZ5K5th",
            valid=True,
            scriptAddress=ByteArray(
                "028f53838b7639563f27c94845549a41e5146bcd52e7fef0ea6da143a02b0fe2ed"
            ),
            f=lambda: addrPK(
                ByteArray(
                    "028f53838b7639563f27c94845549a41e5146bcd52e7fef0ea6da143a02b0fe2ed"
                ),
                mainnet,
            ),
            net=mainnet,
            skipComp=True,
        )
    )
    tests.append(
        test(
            name="mainnet p2pk compressed (0x03)",
            addr="DsfiE2y23CGwKNxSGjbfPGeEW4xw1tamZdc",
            encoded="DsfiE2y23CGwKNxSGjbfPGeEW4xw1tamZdc",
            valid=True,
            scriptAddress=ByteArray(
                "03e925aafc1edd44e7c7f1ea4fb7d265dc672f204c3d0c81930389c10b81fb75de"
            ),
            f=lambda: addrPK(
                ByteArray(
                    "03e925aafc1edd44e7c7f1ea4fb7d265dc672f204c3d0c81930389c10b81fb75de"
                ),
                mainnet,
            ),
            net=mainnet,
            skipComp=True,
        )
    )
    tests.append(
        test(
            name="mainnet p2pk uncompressed (0x04)",
            addr="DkM3EyZ546GghVSkvzb6J47PvGDyntqiDtFgipQhNj78Xm2mUYRpf",
            encoded="DsfFjaADsV8c5oHWx85ZqfxCZy74K8RFuhK",
            valid=True,
            saddr="0264c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f0",
            scriptAddress=ByteArray(
                "0464c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f"
                "0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"
            ),
            f=lambda: addrPK(
                ByteArray(
                    "0464c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f"
                    "0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"
                ),
                mainnet,
            ),
            net=mainnet,
        )
    )
    tests.append(
        test(
            name="testnet p2pk compressed (0x02)",
            addr="Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
            encoded="Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
            valid=True,
            scriptAddress=ByteArray(
                "026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e"
            ),
            f=lambda: addrPK(
                ByteArray(
                    "026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e"
                ),
                testnet,
            ),
            net=testnet,
            skipComp=True,
        )
    )
    tests.append(
        test(
            name="testnet p2pk compressed (0x03)",
            addr="TsWZ1EzypJfMwBKAEDYKuyHRGctqGAxMje2",
            encoded="TsWZ1EzypJfMwBKAEDYKuyHRGctqGAxMje2",
            valid=True,
            scriptAddress=ByteArray(
                "030844ee70d8384d5250e9bb3a6a73d4b5bec770e8b31d6a0ae9fb739009d91af5"
            ),
            f=lambda: addrPK(
                ByteArray(
                    "030844ee70d8384d5250e9bb3a6a73d4b5bec770e8b31d6a0ae9fb739009d91af5"
                ),
                testnet,
            ),
            net=testnet,
            skipComp=True,
        )
    )
    tests.append(
        test(
            name="testnet p2pk uncompressed (0x04)",
            addr="TkKmMiY5iDh4U3KkSopYgkU1AzhAcQZiSoVhYhFymZHGMi9LM9Fdt",
            encoded="Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
            valid=True,
            saddr="026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e",
            scriptAddress=ByteArray(
                "046a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06"
                "ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"
            ),
            f=lambda: addrPK(
                ByteArray(
                    "046a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06"
                    "ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"
                ),
                testnet,
            ),
            net=testnet,
        )
    )

    # Negative P2PK tests.
    tests.append(
        test(
            name="mainnet p2pk hybrid (0x06)",
            addr="",
            valid=False,
            f=lambda: addrPK(
                ByteArray(
                    "0664c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f"
                    "0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"
                ),
                mainnet,
            ),
            net=mainnet,
        )
    )
    tests.append(
        test(
            name="mainnet p2pk hybrid (0x07)",
            addr="",
            valid=False,
            f=lambda: addrPK(
                ByteArray(
                    "07348d8aeb4253ca52456fe5da94ab1263bfee16bb8192497f666389ca964f847"
                    "98375129d7958843b14258b905dc94faed324dd8a9d67ffac8cc0a85be84bac5d"
                ),
                mainnet,
            ),
            net=mainnet,
        )
    )
    tests.append(
        test(
            name="testnet p2pk hybrid (0x06)",
            addr="",
            valid=False,
            f=lambda: addrPK(
                ByteArray(
                    "066a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06"
                    "ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"
                ),
                testnet,
            ),
            net=testnet,
        )
    )
    tests.append(
        test(
            name="testnet p2pk hybrid (0x07)",
            addr="",
            valid=False,
            f=lambda: addrPK(
                ByteArray(
                    "07edd40747de905a9becb14987a1a26c1adbd617c45e1583c142a635bfda9493d"
                    "fa1c6d36735974965fe7b861e7f6fcc087dc7fe47380fa8bde0d9c322d53c0e89"
                ),
                testnet,
            ),
            net=testnet,
        )
    )

    for test in tests:
        # Decode addr and compare error against valid.
        err = None
        try:
            decoded = addrlib.decodeAddress(test.addr, test.net)
        except DecredError as e:
            err = e
        assert (err is None) == test.valid, f"{test.name} error: {err}"

        if err is None:
            # Ensure the stringer returns the same address as the original.
            assert test.addr == decoded.string(), test.name

            # Encode again and compare against the original.
            encoded = decoded.address()
            assert test.encoded == encoded

            # Perform type-specific calculations.
            if isinstance(decoded, addrlib.AddressPubKeyHash):
                d = ByteArray(b58decode(encoded))
                saddr = d[2 : 2 + crypto.RIPEMD160_SIZE]

            elif isinstance(decoded, addrlib.AddressScriptHash):
                d = ByteArray(b58decode(encoded))
                saddr = d[2 : 2 + crypto.RIPEMD160_SIZE]

            elif isinstance(decoded, addrlib.AddressSecpPubKey):
                # Ignore the error here since the script
                # address is checked below.
                try:
                    saddr = ByteArray(decoded.string())
                except ValueError:
                    saddr = test.saddr

            else:
                raise AssertionError(
                    f"Decoded address is of unknown type {type(decoded)}"
                )

            # Check script address, as well as the Hash160 method for P2PKH and
            # P2SH addresses.
            assert saddr == decoded.scriptAddress(), test.name

            if isinstance(decoded, addrlib.AddressPubKeyHash):
                assert decoded.pkHash == saddr

            if isinstance(decoded, addrlib.AddressScriptHash):
                assert decoded.hash160() == saddr

        if not test.valid:
            # If address is invalid, but a creation function exists,
            # verify that it raises a DecredError.
            if test.f is not None:
                try:
                    test.f()
                    raise AssertionError("invalid tests should raise exception")
                except DecredError:
                    pass
            continue

        # Valid test, compare address created with f against expected result.
        addr = test.f()
        assert addr != object()
        if not test.skipComp:
            assert decoded == addr, test.name
            assert decoded == addr.string(), test.name
            assert addr.string() == decoded, test.name
        assert addr.scriptAddress() == test.scriptAddress, test.name

        # Test blobbing
        b = addrlib.Address.blob(addr)
        reAddr = addrlib.Address.unblob(b)
        assert addr == reAddr
