"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.util.encode import BuildyBytes, ByteArray, decodeBlob, extractPushes


class TestEncode:
    def test_ByteArray(self):
        makeA = lambda: ByteArray([0, 0, 255])
        makeB = lambda: ByteArray([0, 255, 0])
        makeC = lambda: ByteArray([255, 0, 0])
        zero = ByteArray([0, 0, 0])

        a = makeA()
        b = makeB()
        a |= b
        assert a == bytearray([0, 255, 255])

        c = makeC()
        a &= c
        assert a == zero

        a = makeA()
        a.zero()
        assert a == zero

        c = makeA()
        c |= 0
        assert a == zero

        a = makeA()
        c = makeC()
        assert a & c == zero

        assert makeA().iseven() is False
        assert makeB().iseven()
        assert makeC().iseven()
        assert zero.iseven()

        zero2 = ByteArray(zero)
        assert zero.b is not zero2.b
        assert zero == zero2

        zero2 = ByteArray(zero, copy=False)
        assert zero.b is zero2.b

        a = makeA()
        a |= makeC()
        a |= 65280
        assert a == bytearray([255, 255, 255])
        assert a != makeB()
        assert a != None  # noqa

        assert makeA() < makeB()
        assert makeC() > makeB()
        assert makeA() != makeB()
        assert not (makeA() == None)  # noqa
        assert makeA() != None  # noqa
        assert makeA() <= makeA()
        assert makeB() >= makeA()

        a = makeA()
        a2 = ByteArray(zero)
        a2 |= a[2:]
        assert a is not a2
        assert a == a2
        assert a[2] == 255

        z = ByteArray(zero)
        z[2] = 255
        assert makeA() == z

        # encode.Blobber API
        assert isinstance(ByteArray.unblob(zero), ByteArray)
        assert ByteArray.blob(zero) == zero.b

        with pytest.raises(DecredError):
            zero[3] = 0

    def test_BuildyBytes(self):
        assert BuildyBytes().hex() == ""

        d0 = ByteArray([0x01, 0x02])
        d1 = ByteArray([0x03, 0x04, 0x05])
        d2 = ByteArray(b"")
        res = BuildyBytes(0).addData(d0).addData(d1).addData(d2)
        exp = ByteArray([0x00, 0x02, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x00])
        assert res == exp

        # Now do a versioned blob with a data push > 255 bytes.
        dBig = ByteArray(b"", length=257)
        dBig[100] = 0x12
        res = BuildyBytes(5).addData(d0).addData(d1).addData(d2).addData(dBig)
        ver, pushes = decodeBlob(res)
        assert ver == 5
        assert d0 == pushes[0]
        assert d1 == pushes[1]
        assert d2 == pushes[2]
        assert dBig == pushes[3]

        dHuge = ByteArray(b"", length=65536)
        with pytest.raises(DecredError):
            BuildyBytes(0).addData(dHuge)

    def test_decodeBlob(self):
        with pytest.raises(DecredError):
            decodeBlob(b"")
        assert decodeBlob(bytes((0, 0x01, 0x02))) == (0, [b"\x02"])

    def test_extractPushes(self):
        assert len(extractPushes(b"")) == 0

        with pytest.raises(DecredError):
            extractPushes(ByteArray([0xFF]))

        assert extractPushes(ByteArray([0xFF, 0x00, 0x00])) == [ByteArray()]

        with pytest.raises(DecredError):
            extractPushes(ByteArray([0x01]))

        assert extractPushes(ByteArray([0x00])) == [ByteArray()]
        assert extractPushes(ByteArray([0x01, 0x00])) == [ByteArray([0x00])]
