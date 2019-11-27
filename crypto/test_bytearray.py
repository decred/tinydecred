"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest
from tinydecred.crypto.bytearray import ByteArray

class TestByteArray(unittest.TestCase):
    def test_operators(self):
        makeA = lambda: ByteArray(bytearray([0, 0, 255]))
        makeB = lambda: ByteArray(bytearray([0, 255, 0]))
        makeC = lambda: ByteArray(bytearray([255, 0, 0]))
        zero = ByteArray(bytearray([0, 0, 0]))

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

        self.assertTrue(makeA() < makeB())
        self.assertTrue(makeC() > makeB())
        self.assertTrue(makeA() != makeB())
        self.assertTrue(makeA() <= makeA())
        self.assertTrue(makeB() >= makeA())

        a = makeA()
        a2 = ByteArray(zero)
        a2 |= a[2:]
        self.assertTrue(not a is a2)
        self.assertEqual(a, a2)
        self.assertEqual(a[2], 255)

        z = ByteArray(zero)
        z[2] = 255
        self.assertEqual(makeA(), z)
