"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

from decred.crypto.secp256k1 import field


H1 = "b3d9aac9c5e43910b4385b53c7e78c21d4cd5f8e683c633aed04c233efc2e120"
H2 = "b0ba920360ea8436a216128047aab9766d8faf468895eb5090fc8241ec758896"


class Test_FieldVal:
    def test_normalize(self, benchmark):
        f = field.FieldVal()
        f.n = [0xFFFFFFFF, 0xFFFFFFC0, 0xFC0, 0, 0, 0, 0, 0, 0, 0]
        benchmark(f.normalize)

    def test_negate(self, benchmark):
        f = field.FieldVal.fromHex(H1)
        benchmark(f.negate, 1)

    def test_add(self, benchmark):
        f1 = field.FieldVal.fromHex(H1)
        f2 = field.FieldVal.fromHex(H2)
        benchmark(f1.add, f2)

    def test_add2(self, benchmark):
        f1 = field.FieldVal.fromHex(H1)
        f2 = field.FieldVal.fromHex(H2)
        benchmark(f1.add2, f1, f2)

    def test_square(self, benchmark):
        f = field.FieldVal.fromHex(H1)
        benchmark(f.square)

    def test_mul(self, benchmark):
        f = field.FieldVal.fromHex(H1)
        f2 = field.FieldVal.fromHex(H2)
        benchmark(f.mul, f2)

    def test_inverse(self, benchmark):
        f = field.FieldVal.fromHex(H1)
        benchmark(f.inverse)
