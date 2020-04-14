"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""


import random

import pytest

from decred import DecredError
from decred.crypto import gcs, rando
from decred.util.encode import ByteArray, rba


def test_BitReader():
    """
    Ensure that the bit reader and all associated methods work as
    expected including expected errors and corner cases at byte boundaries.
    """

    br = gcs.BitReader(ByteArray(int("11101111", 2)))
    with pytest.raises(DecredError):
        br.readNBits(-1)
    with pytest.raises(DecredError):
        br.readNBits(65)

    """
    Test parameters

    name: test description
    bytes: bytes to use as the bitstream
    perReaderTests: tests to run against same reader
        name (str): test description
        doUnary (bool):  whether or not to perform a unary read
        wantUnary (int):  expected number of consecutive ones
        unaryErr (Exception):   expected error on unary read
        nValBits (int):    number of bits to read from bitstream as uint64
        wantVal (int):  expected value from nValBits read
        bitsErr (Exception):   expected error on bits read
    """
    tests = [
        dict(
            name="unary read on empty bytes error",
            b=ByteArray(""),
            perReaderTests=[
                dict(
                    name="unary read",
                    doUnary=True,
                    wantUnary=0,
                    unaryErr=gcs.EncodingError,
                )
            ],
        ),
        dict(
            name="0 bits read on empty bytes (no error)",
            b=ByteArray(""),
            perReaderTests=[dict(name="0 bit read", nValBits=0, wantVal=0,)],
        ),
        dict(
            name="1 bit read on empty bytes error",
            b=ByteArray(""),
            perReaderTests=[
                dict(name="1 bit read", nValBits=1, bitsErr=gcs.EncodingError,)
            ],
        ),
        dict(
            name="9 bit read on single byte error (straddle byte boundary)",
            b=ByteArray("0f"),
            perReaderTests=[
                dict(name="9 bit read", nValBits=9, bitsErr=gcs.EncodingError,)
            ],
        ),
        dict(
            name="16 bit read on single byte error (byte boundary)",
            b=ByteArray("0f"),
            perReaderTests=[
                dict(name="16 bit read", nValBits=16, bitsErr=gcs.EncodingError,)
            ],
        ),
        dict(
            name="0 bits followed by 8 bits ",
            b=ByteArray("ff"),
            perReaderTests=[
                dict(name="0 bit read", nValBits=0, wantVal=0,),
                dict(name="8 bit read", nValBits=8, wantVal=0xFF,),
            ],
        ),
        dict(
            name="unary 1",
            b=ByteArray("80"),
            perReaderTests=[dict(name="first unary read", doUnary=True, wantUnary=1,)],
        ),
        dict(
            name="unary 2",
            b=ByteArray("c0"),
            perReaderTests=[dict(name="first unary read", doUnary=True, wantUnary=2,)],
        ),
        dict(
            name="unary 9 (more than one byte)",
            b=ByteArray("ff80"),
            perReaderTests=[dict(name="first unary read", doUnary=True, wantUnary=9,)],
        ),
        dict(
            name="unary 0, 1 bit read",
            b=ByteArray("40"),
            perReaderTests=[
                dict(name="unary read", doUnary=True, wantUnary=0,),
                dict(name="1 bit read", nValBits=1, wantVal=1,),
            ],
        ),
        dict(
            name="unary 0, 8 bits read (straddle byte)",
            b=ByteArray("5a80"),
            perReaderTests=[
                dict(name="unary read", doUnary=True, wantUnary=0,),
                dict(name="8 bit read", nValBits=8, wantVal=0xB5,),
            ],
        ),
        dict(
            name="unary 0, 15 bits read (byte boundary)",
            b=ByteArray("5ac5"),
            perReaderTests=[
                dict(name="unary read", doUnary=True, wantUnary=0,),
                dict(name="15 bit read", nValBits=15, wantVal=0x5AC5,),
            ],
        ),
        dict(
            name="unary 0, 16 bits read (straddle 2nd byte boundary)",
            b=ByteArray("5ac580"),
            perReaderTests=[
                dict(name="unary read", doUnary=True, wantUnary=0,),
                dict(name="16 bit read", nValBits=16, wantVal=0xB58B,),
            ],
        ),
        dict(
            name="unary 3, 15 bits read, unary 2",
            b=ByteArray("eac518"),
            perReaderTests=[
                dict(name="first unary read", doUnary=True, wantUnary=3,),
                dict(name="15 bit read", nValBits=15, wantVal=0x5628,),
                dict(name="second unary read", doUnary=True, wantUnary=2,),
            ],
        ),
    ]

    for test in tests:
        # Parse the specified bytes to read and create a bitstream reader from
        # them.
        r = gcs.BitReader(test["b"])

        for prTest in test.get("perReaderTests", []):
            testTag = test["name"] + ": " + prTest["name"]
            # Read unary and ensure expected result if requested.
            if prTest.get("doUnary"):
                unaryErr = prTest.get("unaryErr")
                if unaryErr:
                    with pytest.raises(unaryErr):
                        r.readUnary()
                    continue

                try:
                    gotUnary = r.readUnary()
                except gcs.EncodingError:
                    break

                assert gotUnary == prTest.get("wantUnary", 0), testTag

            # Read specified number of bits as uint64 and ensure expected
            # result.
            bitsErr = prTest.get("bitsErr")
            if bitsErr:
                with pytest.raises(bitsErr):
                    r.readNBits(prTest.get("nValBits", 0))
                    continue

            try:
                gotVal = r.readNBits(prTest.get("nValBits", 0))
            except gcs.EncodingError:
                break

            assert gotVal == prTest.get("wantVal", 0), testTag


def test_filter():
    """
    Ensure that the filters and all associated methods work as expected by using
    various known parameters and contents along with random keys for matching
    purposes.
    """
    # Use a random key for each test instance and log it if the tests fail.
    randKey = rando.newKey()[: gcs.KeySize]
    fixedKey = ByteArray(length=16)

    # Test some error paths.
    f = gcs.FilterV2.deserialize(
        ByteArray(
            "1189af70ad5baf9da83c64e99b18e96a06cd7295a58b32"
            "4e81f09c85d093f1e33dcd6f40f18cfcbe2aeb771d8390"
        )
    )
    member = ByteArray("Alex".encode())
    with pytest.raises(DecredError):
        f.match(key=ByteArray(length=17), data=ByteArray(0x0A0B))

    # random entry doesn't match.
    assert not f.match(key=fixedKey, data=ByteArray("0a"))
    assert not f.matchAny(key=fixedKey, data=[ByteArray("0a")])
    # Filter of all FF gives encoding error, which returns False.
    f.filterData = ByteArray(0xFF)
    assert not f.match(key=fixedKey, data=member)
    assert not f.matchAny(key=fixedKey, data=[member])

    # fmt: off
    # contents1 defines a set of known elements for use in the tests below.
    contents1 = [
        ByteArray(s.encode())
        for s in (
            "Alex", "Bob", "Charlie", "Dick", "Ed", "Frank", "George", "Harry", "Ilya",
            "John", "Kevin", "Larry", "Michael", "Nate", "Owen", "Paul", "Quentin",
        )
    ]

    # contents2 defines a separate set of known elements for use in the tests
    # below.
    contents2 = [
        ByteArray(s.encode())
        for s in (
            "Alice", "Betty", "Charmaine", "Donna", "Edith", "Faina", "Georgia",
            "Hannah", "Ilsbeth", "Jennifer", "Kayla", "Lena", "Michelle", "Natalie",
            "Ophelia", "Peggy", "Queenie",
        )
    ]
    # fmt: on

    tests = [
        dict(
            name="v2 empty filter",
            matchKey=randKey,
            contents=[],
            wantMatches=[],
            fixedKey=fixedKey,
            wantBytes=ByteArray(),
            wantHash=rba(length=32),
        ),
        dict(
            name="v2 filter single nil item produces empty filter",
            matchKey=randKey,
            contents=[ByteArray()],
            wantMatches=[],
            fixedKey=fixedKey,
            wantBytes=bytearray(),
            wantHash=rba(length=32),
        ),
        dict(
            name="v2 filter contents1 with nil item with B=19, M=784931",
            matchKey=randKey,
            contents=[ByteArray()] + contents1,
            wantMatches=contents1,
            fixedKey=fixedKey,
            wantBytes=ByteArray(
                "1189af70ad5baf9da83c64e99b18e96a06cd7295a58b32"
                "4e81f09c85d093f1e33dcd6f40f18cfcbe2aeb771d8390"
            ),
            wantHash=rba(
                "b616838c6090d3e732e775cc2f336ce0b836895f3e0f22d6c3ee4485a6ea5018"
            ),
        ),
        dict(
            name="v2 filter contents1 with B=19, M=784931",
            matchKey=randKey,
            contents=contents1,
            wantMatches=contents1,
            fixedKey=fixedKey,
            wantBytes=ByteArray(
                "1189af70ad5baf9da83c64e99b18e96a06cd7295a58b32"
                "4e81f09c85d093f1e33dcd6f40f18cfcbe2aeb771d8390"
            ),
            wantHash=rba(
                "b616838c6090d3e732e775cc2f336ce0b836895f3e0f22d6c3ee4485a6ea5018"
            ),
        ),
        dict(
            name="v2 filter contents2 with B=19, M=784931",
            matchKey=randKey,
            contents=contents2,
            wantMatches=contents2,
            fixedKey=fixedKey,
            wantBytes=ByteArray(
                "118d4be5372d2f4731c7e1681aefd23028be12306b4d90"
                "701a46b472ee80ad60f9fa86c4d6430cfb495ced604362"
            ),
            wantHash=rba(
                "f3028f42909209120c8bf649fbbc5a70fb907d8997a02c2c1f2eef0e6402cb15"
            ),
        ),
    ]

    for test in tests:
        # Create a filter with the match key for all tests not related to
        # testing serialization.
        f = gcs.FilterV2.deserialize(test["wantBytes"])
        wantN = len(test["contents"]) - sum(1 for d in test["contents"] if len(d) == 0)
        assert f.n == wantN, test["name"]

        # Ensure empty data never matches.
        assert not f.match(test["matchKey"], ByteArray())
        assert not f.matchAny(test["matchKey"], []), test["name"]

        assert not f.matchAny(test["matchKey"], [ByteArray()]), test["name"]

        # Ensure empty filter never matches data.
        if len(test["contents"]) == 0:
            wantMiss = "test".encode()
            assert not f.match(test["matchKey"], wantMiss), test["name"]
            assert not f.matchAny(test["matchKey"], [wantMiss]), test["name"]

        # Ensure all of the expected matches occur individually.
        for wantMatch in test["wantMatches"]:
            assert f.match(test["fixedKey"], wantMatch), test["name"]

        # Ensure a subset of the expected matches works in various orders when
        # matching any.
        if len(test["wantMatches"]) > 0:
            # Create set of data to attempt to match such that only the final
            # item is an element in the filter.
            matches = []
            for data in test["wantMatches"]:
                mutated = ByteArray(data)
                mutated[0] ^= 0x55
                matches.append(mutated)

            matches[-1] = test["wantMatches"][-1]

            assert f.matchAny(test["fixedKey"], matches), test["name"]

            # Fisher-Yates shuffle the match set and test for matches again.
            for i in range(len(matches)):
                # Pick a number between current index and the end.
                j = random.randint(0, len(matches) - i - 1) + i
                matches[i], matches[j] = matches[j], matches[i]

            assert f.matchAny(test["fixedKey"], matches), test["name"]

        assert f.hash() == test["wantHash"], test["name"]
