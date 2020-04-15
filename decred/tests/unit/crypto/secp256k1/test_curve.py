"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import random

import pytest

from decred import DecredError
from decred.crypto.secp256k1 import curve, field
from decred.crypto.secp256k1.curve import curve as curve_obj
from decred.util.encode import ByteArray


def _isJacobianOnS256Curve(x, y, z):
    """
    _isJacobianOnS256Curve returns boolean if the point (x,y,z) is on the
    secp256k1 curve.
    Elliptic curve equation for secp256k1 is: y^2 = x^3 + 7
    In Jacobian coordinates, Y = y/z^3 and X = x/z^2
    Thus:
    (y/z^3)^2 = (x/z^2)^3 + 7
    y^2/z^6 = x^3/z^6 + 7
    y^2 = x^3 + 7*z^6
    """
    fv = field.FieldVal
    y2, z2, x3, result = fv(), fv(), fv(), fv()
    y2.squareVal(y).normalize()
    z2.squareVal(z)
    x3.squareVal(x).mul(x)
    result.squareVal(z2).mul(z2).mulInt(7).add(x3).normalize()
    return y2.equals(result)


def test_addJacobian():
    """
    test_addJacobian tests addition of points projected in Jacobian coordinates.
    """
    tests = [
        # Addition with a point at infinity (left hand side).
        # ∞ + P = P
        (
            "0",
            "0",
            "0",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "1",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "1",
        ),
        # Addition with a point at infinity (right hand side).
        # P + ∞ = P
        (
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "1",
            "0",
            "0",
            "0",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "1",
        ),
        # Addition with z1=z2=1 different x values.
        (
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "1",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "1",
            "0cfbc7da1e569b334460788faae0286e68b3af7379d5504efc25e4dba16e46a6",
            "e205f79361bbe0346b037b4010985dbf4f9e1e955e7d0d14aca876bfa79aad87",
            "44a5646b446e3877a648d6d381370d9ef55a83b666ebce9df1b1d7d65b817b2f",
        ),
        # Addition with z1=z2=1 same x opposite y.
        # P(x, y, z) + P(x, -y, z) = infinity
        (
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "1",
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
            "1",
            "0",
            "0",
            "0",
        ),
        # Addition with z1=z2=1 same point.
        # P(x, y, z) + P(x, y, z) = 2P
        (
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "1",
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "1",
            "ec9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee64f87c50c27",
            "b082b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd0755c8f2a",
            "16e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c1e594464",
        ),
        # Addition with z1=z2 (!=1) different x values.
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "5d2fe112c21891d440f65a98473cb626111f8a234d2cd82f22172e369f002147",
            "98e3386a0a622a35c4561ffb32308d8e1c6758e10ebb1b4ebd3d04b4eb0ecbe8",
            "2",
            "cfbc7da1e569b334460788faae0286e68b3af7379d5504efc25e4dba16e46a60",
            "817de4d86ef80d1ac0ded00426176fd3e787a5579f43452b2a1db021e6ac3778",
            "129591ad11b8e1de99235b4e04dc367bd56a0ed99baf3a77c6c75f5a6e05f08d",
        ),
        # Addition with z1=z2 (!=1) same x opposite y.
        # P(x, y, z) + P(x, -y, z) = infinity
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "a470ab21467813b6e0496d2c2b70c11446bab4fcbc9a52b7f225f30e869aea9f",
            "2",
            "0",
            "0",
            "0",
        ),
        # Addition with z1=z2 (!=1) same point.
        # P(x, y, z) + P(x, y, z) = 2P
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
            "2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
            "6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
        ),
        # Addition with z1!=z2 and z2=1 different x values.
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "1",
            "3ef1f68795a6ccd1181e23eab80a1b9a2cebdcde755413bf097936eb5b91b4f3",
            "0bef26c377c068d606f6802130bb7e9f3c3d2abcfa1a295950ed81133561cb04",
            "252b235a2371c3bd3246b69c09b86cf7aad41db3375e74ef8d8ebeb4dc0be11a",
        ),
        # Addition with z1!=z2 and z2=1 same x opposite y.
        # P(x, y, z) + P(x, -y, z) = infinity
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
            "1",
            "0",
            "0",
            "0",
        ),
        # Addition with z1!=z2 and z2=1 same point.
        # P(x, y, z) + P(x, y, z) = 2P
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "1",
            "9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
            "2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
            "6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
        ),
        # Addition with z1!=z2 and z2!=1 different x values.
        # P(x, y, z) + P(x, y, z) = 2P
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "91abba6a34b7481d922a4bd6a04899d5a686f6cf6da4e66a0cb427fb25c04bd4",
            "03fede65e30b4e7576a2abefc963ddbf9fdccbf791b77c29beadefe49951f7d1",
            "3",
            "3f07081927fd3f6dadd4476614c89a09eba7f57c1c6c3b01fa2d64eac1eef31e",
            "949166e04ebc7fd95a9d77e5dfd88d1492ecffd189792e3944eb2b765e09e031",
            "eb8cba81bcffa4f44d75427506737e1f045f21e6d6f65543ee0e1d163540c931",
        ),
        # Addition with z1!=z2 and z2!=1 same x opposite y.
        # P(x, y, z) + P(x, -y, z) = infinity
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "dcc3768780c74a0325e2851edad0dc8a566fa61a9e7fc4a34d13dcb509f99bc7",
            "cafc41904dd5428934f7d075129c8ba46eb622d4fc88d72cd1401452664add18",
            "3",
            "0",
            "0",
            "0",
        ),
        # Addition with z1!=z2 and z2!=1 same point.
        # P(x, y, z) + P(x, y, z) = 2P
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "dcc3768780c74a0325e2851edad0dc8a566fa61a9e7fc4a34d13dcb509f99bc7",
            "3503be6fb22abd76cb082f8aed63745b9149dd2b037728d32ebfebac99b51f17",
            "3",
            "9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
            "2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
            "6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
        ),
    ]

    # x1, y1, z1 string // Coordinates (in hex) of first point to add
    # x2, y2, z2 string // Coordinates (in hex) of second point to add
    # x3, y3, z3 string // Coordinates (in hex) of expected point
    for i, (x1, y1, z1, x2, y2, z2, x3, y3, z3) in enumerate(tests):
        # Convert hex to field values.
        x1 = curve.FieldVal.fromHex(x1)
        y1 = curve.FieldVal.fromHex(y1)
        z1 = curve.FieldVal.fromHex(z1)
        x2 = curve.FieldVal.fromHex(x2)
        y2 = curve.FieldVal.fromHex(y2)
        z2 = curve.FieldVal.fromHex(z2)
        x3 = curve.FieldVal.fromHex(x3)
        y3 = curve.FieldVal.fromHex(y3)
        z3 = curve.FieldVal.fromHex(z3)

        # Ensure the test data is using points that are actually on
        # the curve (or the point at infinity).
        assert z1.isZero() or _isJacobianOnS256Curve(x1, y1, z1)
        assert z2.isZero() or _isJacobianOnS256Curve(x2, y2, z2)
        assert z3.isZero() or _isJacobianOnS256Curve(x3, y3, z3)

        # Add the two points.
        fv = curve.FieldVal
        rx, ry, rz = fv(), fv(), fv()
        curve_obj.addJacobian(x1, y1, z1, x2, y2, z2, rx, ry, rz)
        assert rx.equals(x3)
        assert ry.equals(y3)
        assert rz.equals(z3)


def test_doubleJacobian():
    """
    test_doubleJacobian tests doubling of points projected in Jacobian
    coordinates.
    """
    tests = [
        # Doubling a point at infinity is still infinity.
        ("0", "0", "0", "0", "0", "0",),
        # Doubling with z1=1.
        (
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "1",
            "ec9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee64f87c50c27",
            "b082b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd0755c8f2a",
            "16e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c1e594464",
        ),
        # Doubling with z1!=1.
        (
            "d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
            "5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
            "2",
            "9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
            "2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
            "6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
        ),
        # From btcd issue #709.
        (
            "201e3f75715136d2f93c4f4598f91826f94ca01f4233a5bd35de9708859ca50d",
            "bdf18566445e7562c6ada68aef02d498d7301503de5b18c6aef6e2b1722412e1",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "4a5e0559863ebb4e9ed85f5c4fa76003d05d9a7626616e614a1f738621e3c220",
            "00000000000000000000000000000000000000000000000000000001b1388778",
            "7be30acc88bceac58d5b4d15de05a931ae602a07bcb6318d5dedc563e4482993",
        ),
    ]

    # x1, y1, z1 string // Coordinates (in hex) of point to double
    # x3, y3, z3 string // Coordinates (in hex) of expected point
    for i, (x1, y1, z1, x3, y3, z3) in enumerate(tests):
        # Convert hex to field values.
        x1 = curve.FieldVal.fromHex(x1)
        y1 = curve.FieldVal.fromHex(y1)
        z1 = curve.FieldVal.fromHex(z1)
        x3 = curve.FieldVal.fromHex(x3)
        y3 = curve.FieldVal.fromHex(y3)
        z3 = curve.FieldVal.fromHex(z3)

        # Ensure the test data is using points that are actually on
        # the curve (or the point at infinity).
        assert z1.isZero() or _isJacobianOnS256Curve(x1, y1, z1)
        assert z3.isZero() or _isJacobianOnS256Curve(x3, y3, z3)
        # Double the point.
        fv = curve.FieldVal
        rx, ry, rz = fv(), fv(), fv()
        curve_obj.doubleJacobian(x1, y1, z1, rx, ry, rz)
        assert rx.equals(x3)
        assert ry.equals(y3)
        assert rz.equals(z3)


def test_scalarBaseMult():
    tests = [
        (
            "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
            "34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
            "B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
        ),
        (
            "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
            "D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
            "131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
        ),
        (
            "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
            "E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
            "C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
        ),
        (
            "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
            "14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
            "297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
        ),
        (
            "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
            "F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
            "F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
        ),
    ]

    for i, (k, x, y) in enumerate(tests):
        px, py = curve_obj.scalarBaseMult(curve.fromHex(k))
        assert px == curve.fromHex(x)
        assert py == curve.fromHex(y)


def test_add():
    """
    test_add tests addition of points in affine coordinates.
    """
    tests = [
        # Addition with a point at infinity (left hand side).
        # ∞ + P = P
        (
            "0",
            "0",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
        ),
        # Addition with a point at infinity (right hand side).
        # P + ∞ = P
        (
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "0",
            "0",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
        ),
        # Addition with different x values.
        (
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
            "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
            "fd5b88c21d3143518d522cd2796f3d726793c88b3e05636bc829448e053fed69",
            "21cf4f6a5be5ff6380234c50424a970b1f7e718f5eb58f68198c108d642a137f",
        ),
        # Addition with same x opposite y.
        # P(x, y) + P(x, -y) = infinity
        (
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
            "0",
            "0",
        ),
        # Addition with same point.
        # P(x, y) + P(x, y) = 2P
        (
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
            "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
            "59477d88ae64a104dbb8d31ec4ce2d91b2fe50fa628fb6a064e22582196b365b",
            "938dc8c0f13d1e75c987cb1a220501bd614b0d3dd9eb5c639847e1240216e3b6",
        ),
    ]

    for i, (x1, y1, x2, y2, x3, y3) in enumerate(tests):
        # Convert hex to field values.
        x1, y1 = curve.fromHex(x1), curve.fromHex(y1)
        x2, y2 = curve.fromHex(x2), curve.fromHex(y2)
        x3, y3 = curve.fromHex(x3), curve.fromHex(y3)

        # Ensure the test data is using points that are actually on
        # the curve (or the point at infinity).
        assert (x1 == 0 and y1 == 0) or curve_obj.isAffineOnCurve(x1, y1)
        assert (x2 == 0 and y2 == 0) or curve_obj.isAffineOnCurve(x2, y2)
        assert (x3 == 0 and y3 == 0) or curve_obj.isAffineOnCurve(x3, y3)

        # Add the two points.
        rx, ry = curve_obj.add(x1, y1, x2, y2)

        # Ensure result matches expected.
        assert rx == x3
        assert ry == y3


def _check_NAF(i, want):
    """
    Args:
        i: integer
        want: ByteArray
    """
    nafPos, nafNeg = curve.NAF(want)
    got = 0
    # Check that the NAF representation comes up with the right number.
    for j in range(len(nafPos)):
        bytePos = nafPos[j]
        byteNeg = nafNeg[j]
        for _ in range(8):
            got *= 2
            if bytePos & 0x80 == 0x80:
                got += 1
            elif byteNeg & 0x80 == 0x80:
                got -= 1
            bytePos <<= 1
            byteNeg <<= 1
    assert got == want.int(), f"test {i}"


def test_NAF():
    tests = (
        "6df2b5d30854069ccdec40ae022f5c948936324a4e9ebed8eb82cfd5a6b6d766",
        "b776e53fb55f6b006a270d42d64ec2b1",
        "d6cc32c857f1174b604eefc544f0c7f7",
        "45c53aa1bb56fcd68c011e2dad6758e4",
        "a2e79d200f27f2360fba57619936159b",
    )
    for i, test in enumerate(tests):
        _check_NAF(i, ByteArray(test))


def test_NAF_rand(randBytes):
    random.seed(0)
    for i in range(1024):
        data = ByteArray(randBytes(0, 32))
        _check_NAF(i, data)


def test_splitK(sign):
    tests = [
        dict(
            k="6df2b5d30854069ccdec40ae022f5c948936324a4e9ebed8eb82cfd5a6b6d766",
            k1="00000000000000000000000000000000b776e53fb55f6b006a270d42d64ec2b1",
            k2="00000000000000000000000000000000d6cc32c857f1174b604eefc544f0c7f7",
            s1=-1,
            s2=-1,
        ),
        dict(
            k="6ca00a8f10632170accc1b3baf2a118fa5725f41473f8959f34b8f860c47d88d",
            k1="0000000000000000000000000000000007b21976c1795723c1bfbfa511e95b84",
            k2="00000000000000000000000000000000d8d2d5f9d20fc64fd2cf9bda09a5bf90",
            s1=1,
            s2=-1,
        ),
        dict(
            k="b2eda8ab31b259032d39cbc2a234af17fcee89c863a8917b2740b67568166289",
            k1="00000000000000000000000000000000507d930fecda7414fc4a523b95ef3c8c",
            k2="00000000000000000000000000000000f65ffb179df189675338c6185cb839be",
            s1=-1,
            s2=-1,
        ),
        dict(
            k="f6f00e44f179936f2befc7442721b0633f6bafdf7161c167ffc6f7751980e3a0",
            k1="0000000000000000000000000000000008d0264f10bcdcd97da3faa38f85308d",
            k2="0000000000000000000000000000000065fed1506eb6605a899a54e155665f79",
            s1=-1,
            s2=-1,
        ),
        dict(
            k="8679085ab081dc92cdd23091ce3ee998f6b320e419c3475fae6b5b7d3081996e",
            k1="0000000000000000000000000000000089fbf24fbaa5c3c137b4f1cedc51d975",
            k2="00000000000000000000000000000000d38aa615bd6754d6f4d51ccdaf529fea",
            s1=-1,
            s2=-1,
        ),
        dict(
            k="6b1247bb7931dfcae5b5603c8b5ae22ce94d670138c51872225beae6bba8cdb3",
            k1="000000000000000000000000000000008acc2a521b21b17cfb002c83be62f55d",
            k2="0000000000000000000000000000000035f0eff4d7430950ecb2d94193dedc79",
            s1=-1,
            s2=-1,
        ),
        dict(
            k="a2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba219b51835b55cc30ebfe2f6599bc56f58",
            k1="0000000000000000000000000000000045c53aa1bb56fcd68c011e2dad6758e4",
            k2="00000000000000000000000000000000a2e79d200f27f2360fba57619936159b",
            s1=-1,
            s2=-1,
        ),
    ]
    for test in tests:
        k = ByteArray(test["k"]).int()
        k1int, k2int = curve_obj.splitK(k)
        k1sign, k1 = sign(k1int), abs(k1int)
        k2sign, k2 = sign(k2int), abs(k2int)
        assert f"{k1:064x}" == test["k1"]
        assert f"{k2:064x}" == test["k2"]
        assert k1sign == test["s1"]
        assert k2sign == test["s2"]
        gotk = k2int * curve_obj.lambda_
        gotk += k1int
        gotk %= curve_obj.N
        assert gotk == k


def test_splitK_rand(randBytes):
    random.seed(0)
    for _ in range(1024):
        k = ByteArray(randBytes(0, 32)).int()
        k1, k2 = curve_obj.splitK(k)
        gotk = k2 * curve_obj.lambda_
        gotk += k1
        gotk %= curve_obj.N
        assert gotk == k


def test_scalarMult():
    tests = [
        # base mult, essentially.
        dict(
            x="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            y="483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            k="18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
            rx="50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
            ry="2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",
        ),
        # From btcd issue #709.
        dict(
            x="000000000000000000000000000000000000000000000000000000000000002c",
            y="420e7a99bba18a9d3952597510fd2b6728cfeafc21a4e73951091d4d8ddbe94e",
            k="a2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba219b51835b55cc30ebfe2f6599bc56f58",
            rx="a2112dcdfbcd10ae1133a358de7b82db68e0a3eb4b492cc8268d1e7118c98788",
            ry="27fc7463b7bb3c5f98ecf2c84a6272bb1681ed553d92c69f2dfe25a9f9fd3836",
        ),
    ]

    for test in tests:
        x = ByteArray(test["x"]).int()
        y = ByteArray(test["y"]).int()
        k = ByteArray(test["k"]).int()
        x_want = ByteArray(test["rx"]).int()
        y_want = ByteArray(test["ry"]).int()
        x_got, y_got = curve_obj.scalarMult(x, y, k)
        assert x_got == x_want
        assert y_got == y_want


def test_scalarMult_rand(randBytes):
    # Strategy for this test:
    # Get a random exponent from the generator point at first.
    # This creates a new point which is used in the next iteration.
    # Use another random exponent on the new point.
    # We use BaseMult to verify by multiplying the previous exponent
    # and the new random exponent together (mod N).
    x, y = curve_obj.Gx, curve_obj.Gy
    exponent = 1
    for _ in range(1024):
        data = ByteArray(randBytes(0, 32)).int()
        x, y = curve_obj.scalarMult(x, y, data)
        exponent *= data
        x_want, y_want = curve_obj.scalarBaseMult(exponent)
        assert x == x_want
        assert y == y_want


def test_PublicKey():
    # fmt: off
    tests = [
        # pubkey from bitcoin blockchain tx
        # 0437cd7f8525ceed2324359c2d0ba26006d92d85
        dict(
            name="uncompressed ok",
            key=bytes((
                0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa3,
            )),
            isValid=True,
            format="pubkeyUncompressed",
        ),
        dict(
            name="uncompressed x changed",
            key=bytes((
                0x04, 0x15, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa3,
            )),
            isValid=False,
        ),
        dict(
            name="uncompressed y changed",
            key=bytes((
                0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa4,
            )),
            isValid=False,
        ),
        dict(
            name="uncompressed claims compressed",
            key=bytes((
                0x03, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa3,
            )),
            isValid=False,
        ),
        dict(
            name="uncompressed as hybrid ok",
            key=bytes((
                0x07, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa3,
            )),
            isValid=False,
        ),
        dict(
            name="uncompressed as hybrid wrong",
            key=bytes((
                0x06, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa3,
            )),
            isValid=False,
        ),
        # from tx 0b09c51c51ff762f00fb26217269d2a18e77a4fa87d69b3c363ab4df16543f20
        dict(
            name="compressed ok (ybit = 0)",
            key=bytes((

                0x02, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b,
                0xa5, 0x49, 0xfd, 0xd6, 0x75, 0xc9, 0x80, 0x75, 0xf1,
                0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21,
                0xa9, 0xa1, 0xf4, 0x80, 0x9d, 0x3b, 0x4d,
            )),
            isValid=True,
            format="pubkeyCompressed",
        ),
        # from tx fdeb8e72524e8dab0da507ddbaf5f88fe4a933eb10a66bc4745bb0aa11ea393c
        dict(
            name="compressed ok (ybit = 1)",
            key=bytes((
                0x03, 0x26, 0x89, 0xc7, 0xc2, 0xda, 0xb1, 0x33,
                0x09, 0xfb, 0x14, 0x3e, 0x0e, 0x8f, 0xe3, 0x96, 0x34,
                0x25, 0x21, 0x88, 0x7e, 0x97, 0x66, 0x90, 0xb6, 0xb4,
                0x7f, 0x5b, 0x2a, 0x4b, 0x7d, 0x44, 0x8e,
            )),
            isValid=True,
            format="pubkeyCompressed",
        ),
        dict(
            name="compressed claims uncompressed (ybit = 0)",
            key=bytes((
                0x04, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b,
                0xa5, 0x49, 0xfd, 0xd6, 0x75, 0xc9, 0x80, 0x75, 0xf1,
                0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21,
                0xa9, 0xa1, 0xf4, 0x80, 0x9d, 0x3b, 0x4d,
            )),
            isValid=False,
        ),
        dict(
            name="compressed claims uncompressed (ybit = 1)",
            key=bytes((
                0x05, 0x26, 0x89, 0xc7, 0xc2, 0xda, 0xb1, 0x33,
                0x09, 0xfb, 0x14, 0x3e, 0x0e, 0x8f, 0xe3, 0x96, 0x34,
                0x25, 0x21, 0x88, 0x7e, 0x97, 0x66, 0x90, 0xb6, 0xb4,
                0x7f, 0x5b, 0x2a, 0x4b, 0x7d, 0x44, 0x8e,
            )),
            isValid=False,
        ),
        dict(
            name="wrong length",
            key=bytes(0x05),
            isValid=False,
        ),
        dict(
            name="X == P",
            key=bytes((
                0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa3,
            )),
            isValid=False,
        ),
        dict(
            name="X > P",
            key=bytes((
                0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFD, 0x2F, 0xb2, 0xe0,
                0xea, 0xdd, 0xfb, 0x84, 0xcc, 0xf9, 0x74, 0x44, 0x64,
                0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64, 0xf9,
                0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56,
                0xb4, 0x12, 0xa3,
            )),
            isValid=False,
        ),
        dict(
            name="Y == P",
            key=bytes((
                0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF,
                0xFF, 0xFC, 0x2F,
            )),
            isValid=False,
        ),
        dict(
            name="Y > P",
            key=bytes((
                0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a,
                0x01, 0x6b, 0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e,
                0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF,
                0xFF, 0xFD, 0x2F,
            )),
            isValid=False,
        ),
        dict(
            name="hybrid",
            key=bytes((
                0x06, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
                0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
                0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59,
                0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a,
                0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb,
                0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48,
                0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb,
                0x10, 0xd4, 0xb8,
            )),
            isValid=False,
        ),
        dict(
            name="empty",
            key=bytes(),
            isValid=False,
        ),
    ]
    # fmt: on
    for test in tests:
        if test["isValid"]:
            pk = curve_obj.parsePubKey(test["key"])
        else:
            with pytest.raises(DecredError):
                curve_obj.parsePubKey(test["key"])
            # Invalid key has no serialization format.
            continue
        if test["format"] == "pubkeyCompressed":
            pkStr = pk.serializeCompressed()
        elif test["format"] == "pubkeyUncompressed":
            pkStr = pk.serializeUncompressed()
        else:
            raise RuntimeError(
                "Key {} is valid but serialization is unknown: {}".format(
                    test["name"], test["format"]
                )
            )
        assert pkStr == ByteArray(test["key"])


def test_PublicKey_eq():
    # fmt: off
    pubKey1 = curve_obj.parsePubKey(
        bytes((
            0x03, 0x26, 0x89, 0xc7, 0xc2, 0xda, 0xb1, 0x33,
            0x09, 0xfb, 0x14, 0x3e, 0x0e, 0x8f, 0xe3, 0x96, 0x34,
            0x25, 0x21, 0x88, 0x7e, 0x97, 0x66, 0x90, 0xb6, 0xb4,
            0x7f, 0x5b, 0x2a, 0x4b, 0x7d, 0x44, 0x8e,
        ))
    )
    pubKey2 = curve_obj.parsePubKey(
        bytes((
            0x02, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b,
            0xa5, 0x49, 0xfd, 0xd6, 0x75, 0xc9, 0x80, 0x75, 0xf1,
            0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21,
            0xa9, 0xa1, 0xf4, 0x80, 0x9d, 0x3b, 0x4d,
        ))
    )
    # fmt: on
    assert pubKey1 == pubKey1
    assert pubKey1 != pubKey2
