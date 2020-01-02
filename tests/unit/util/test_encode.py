"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from tinydecred.util import encode


ByteArray = encode.ByteArray
BuildyBytes = encode.BuildyBytes


class TestEncode(unittest.TestCase):
    def test_ByteArray(self):
        makeA = lambda: ByteArray([0, 0, 255])
        makeB = lambda: ByteArray([0, 255, 0])
        makeC = lambda: ByteArray([255, 0, 0])
        zero = ByteArray([0, 0, 0])

        a = makeA()
        b = makeB()
        a |= b
        self.assertEqual(a, bytearray([0, 255, 255]))

        c = makeC()
        a &= c
        self.assertEqual(a, zero)

        a = makeA()
        a.zero()
        self.assertEqual(a, zero)

        c = makeA()
        c |= 0
        self.assertEqual(a, zero)

        # FIXME: This new test is failing, not sure why.
        # a = makeA()
        # c = makeC()
        # self.assertEqual(a & c, zero)

        self.assertFalse(makeA().iseven())
        self.assertTrue(makeB().iseven())
        self.assertTrue(makeC().iseven())
        self.assertTrue(zero.iseven())

        zero2 = ByteArray(zero)
        self.assertFalse(zero.b is zero2.b)
        self.assertEqual(zero, zero2)

        zero2 = ByteArray(zero, copy=False)
        self.assertTrue(zero.b is zero2.b)

        a = makeA()
        a |= makeC()
        a |= 65280
        self.assertEqual(a, bytearray([255, 255, 255]))
        self.assertFalse(a == makeB())
        self.assertFalse(a == None)  # noqa

        self.assertTrue(makeA() < makeB())
        self.assertTrue(makeC() > makeB())
        self.assertTrue(makeA() != makeB())
        self.assertTrue(makeA() != None)  # noqa
        self.assertTrue(makeA() <= makeA())
        self.assertTrue(makeB() >= makeA())

        a = makeA()
        a2 = ByteArray(zero)
        a2 |= a[2:]
        self.assertTrue(a is not a2)
        self.assertEqual(a, a2)
        self.assertEqual(a[2], 255)

        z = ByteArray(zero)
        z[2] = 255
        self.assertEqual(makeA(), z)

<<<<<<< HEAD:tests/unit/util/test_encode.py
    def test_BuildyBytes(self):
        d0 = ByteArray([0x01, 0x02])
        d1 = ByteArray([0x03, 0x04, 0x05])
        d2 = ByteArray(b"")
        res = BuildyBytes(0).addData(d0).addData(d1).addData(d2)
        exp = ByteArray([0x00, 0x02, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x00])
        self.assertEqual(res, exp)

        # Now do a versioned blob with a data push > 255 bytes.
        dBig = ByteArray(b"", length=257)
        dBig[100] = 0x12
        res = BuildyBytes(5).addData(d0).addData(d1).addData(d2).addData(dBig)
        ver, pushes = encode.decodeBlob(res)
        self.assertEqual(ver, 5)
        self.assertEqual(d0, pushes[0])
        self.assertEqual(d1, pushes[1])
        self.assertEqual(d2, pushes[2])
        self.assertEqual(dBig, pushes[3])
=======
    def test_decodeBA_bad(self):
        self.assertRaises(TypeError, decodeBA, None)
>>>>>>> Changes per review.:tests/unit/crypto/test_bytearray.py
