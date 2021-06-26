"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.btc.wire import msgtx, wire
from decred.util.encode import ByteArray


def test_txHash():
    """
    test_txHash tests the ability to generate the hash of a transaction accurately.
    """
    # Hash of first transaction from block 113875.
    txid = "f051e59b5e2503ac626d03aaeac8ab7be2d72ba4b7e97119c5852d70d52dcb86"
    wantHash = reversed(ByteArray(txid))

    # First transaction from block 113875.
    msgTx = msgtx.MsgTx()
    txIn = msgtx.TxIn(
        previousOutPoint=msgtx.OutPoint(
            txHash=ByteArray(length=32),
            idx=0xffffffff,
        ),
        signatureScript=ByteArray("0431dc001b0162"),
        sequence=0xffffffff,
    )
    txOut = msgtx.TxOut(
        value=5000000000,
        pkScript=ByteArray([
            0x41,  # OP_DATA_65
            0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
            0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
            0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
            0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
            0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
            0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
            0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
            0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
            0xa6,  # 65-byte signature
            0xac,  # OP_CHECKSIG
        ]),
    )
    msgTx.addTxIn(txIn)
    msgTx.addTxOut(txOut)
    # msgTx.lockTime = 0

    # Ensure the hash produced is expected.
    assert msgTx.hash() == wantHash


def test_wTxSha():
    """
    test_wTxSha tests the ability to generate the wtxid, and txid of a transaction
    with witness inputs accurately.
    """
    txid = "0f167d1385a84d1518cfee208b653fc9163b605ccf1b75347e2850b3e2eb19f3"
    wantHash = reversed(ByteArray(txid))

    wTxid = "0858eab78e77b6b033da30f46699996396cf48fcf625a783c85a51403e175e74"
    wantWitnessHash = reversed(ByteArray(wTxid))

    # From block 23157 in a past version of segnet.
    msgTx = msgtx.MsgTx()
    txIn = msgtx.TxIn(
        previousOutPoint=msgtx.OutPoint(
            txHash=ByteArray("a53352d5135766f03076597418263da2d9c958315968fea823529467481ff9cd"),
            idx=19,
        ),
        witness=[
            ByteArray(  # 70-byte signature
                "3043021f4d2381dc97f182abd8185f51753018523212f5ddc07cc4e63a8dc03658da190220608b5c4d92b86b6de7d78ef23a2fa735bcb59b914a48b0e187c5e7569a18197001",
            ),
            ByteArray(  # 33-byte serialize pub key
                "0307ead084807eb76346df6977000c89392f45c76425b26181f521d7f370066a8f",
            ),
        ],
        sequence=0xffffffff,
    )
    txOut = msgtx.TxOut(
        value=395019,
        pkScript=ByteArray([
            0x00,  # Version 0 witness program
            0x14,  # OP_DATA_20
            0x9d, 0xda, 0xc6, 0xf3, 0x9d, 0x51, 0xe0, 0x39,
            0x8e, 0x53, 0x2a, 0x22, 0xc4, 0x1b, 0xa1, 0x89,
            0x40, 0x6a, 0x85, 0x23,  # 20-byte pub key hash
        ]),
    )
    msgTx.addTxIn(txIn)
    msgTx.addTxOut(txOut)
    # msgTx.LockTime = 0

    # Ensure the correct txid, and wtxid is produced as expected.
    assert msgTx.hash() == wantHash
    assert msgTx.witnessHash() == wantWitnessHash


def test_TxWire():
    """
    test_TxWire tests the MsgTx wire encode and decode for various numbers
    of transaction inputs and outputs and protocol versions.
    """
    # Empty tx message.
    noTx = msgtx.MsgTx(version=1)
    noTxEncoded = ByteArray([
        0x01, 0x00, 0x00, 0x00,  # Version
        0x00,                    # Varint for number of input transactions
        0x00,                    # Varint for number of output transactions
        0x00, 0x00, 0x00, 0x00,  # Lock time
    ])

    tests = [
        dict(
            inTx=noTx,
            out=noTx,
            buf=noTxEncoded,
            pver=wire.ProtocolVersion,
            enc=msgtx.BaseEncoding,
        ),

        # Latest protocol version with multiple transactions.
        dict(
            inTx=multiTx,
            out=multiTx,
            buf=multiTxEncoded,
            pver=wire.ProtocolVersion,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version BIP0035Version with no transactions.
        dict(
            inTx=noTx,
            out=noTx,
            buf=noTxEncoded,
            pver=wire.BIP0035Version,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version BIP0035Version with multiple transactions.
        dict(
            inTx=multiTx,
            out=multiTx,
            buf=multiTxEncoded,
            pver=wire.BIP0035Version,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version BIP0031Version with no transactions.
        dict(
            inTx=noTx,
            out=noTx,
            buf=noTxEncoded,
            pver=wire.BIP0031Version,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version BIP0031Version with multiple transactions.
        dict(
            inTx=multiTx,
            out=multiTx,
            buf=multiTxEncoded,
            pver=wire.BIP0031Version,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version NetAddressTimeVersion with no transactions.
        dict(
            inTx=noTx,
            out=noTx,
            buf=noTxEncoded,
            pver=wire.NetAddressTimeVersion,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version NetAddressTimeVersion with multiple transactions.
        dict(
            inTx=multiTx,
            out=multiTx,
            buf=multiTxEncoded,
            pver=wire.NetAddressTimeVersion,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version MultipleAddressVersion with no transactions.
        dict(
            inTx=noTx,
            out=noTx,
            buf=noTxEncoded,
            pver=wire.MultipleAddressVersion,
            enc=msgtx.BaseEncoding,
        ),

        # # Protocol version MultipleAddressVersion with multiple transactions.
        dict(
            inTx=multiTx,
            out=multiTx,
            buf=multiTxEncoded,
            pver=wire.MultipleAddressVersion,
            enc=msgtx.BaseEncoding,
        ),
    ]

    for test in tests:
        # Encode the message to wire format.
        b = test["inTx"].btcEncode(test["pver"], test["enc"])
        assert b == test["buf"]

        msgTx = msgtx.MsgTx.btcDecode(test["buf"].copy(), test["pver"], test["enc"])
        assert msgTx == test["out"]


def test_TxSerialize():
    """
    test_TxSerialize tests MsgTx serialize and deserialize.
    """
    noTx = msgtx.MsgTx(version=1)
    noTxEncoded = ByteArray([
        0x01, 0x00, 0x00, 0x00,  # Version
        0x00,                    # Varint for number of input transactions
        0x00,                    # Varint for number of output transactions
        0x00, 0x00, 0x00, 0x00,  # Lock time
    ])

    tests = [
        # No transactions.
        dict(
            inTx=noTx,
            out=noTx,
            buf=noTxEncoded,
            pkScriptLocs=[],
            witness=False,
        ),

        # Multiple transactions.
        dict(
            inTx=multiTx,
            out=multiTx,
            buf=multiTxEncoded,
            pkScriptLocs=multiTxPkScriptLocs,
            witness=True,
        ),
        # Multiple outputs witness transaction.
        dict(
            inTx=multiWitnessTx,
            out=multiWitnessTx,
            buf=multiWitnessTxEncoded,
            pkScriptLocs=multiWitnessTxPkScriptLocs,
            witness=True,
        ),
    ]

    for i, test in enumerate(tests):
        # Serialize the transaction.
        buf = test["inTx"].serialize()
        assert buf == test["buf"]

        # Deserialize the transaction.
        if test["witness"]:
            tx = msgtx.MsgTx.deserialize(test["buf"].copy())
        else:
            tx = msgtx.MsgTx.deserializeNoWitness(test["buf"])

        assert tx == test["out"]

        # Ensure the public key script locations are accurate.
        pkScriptLocs = test["inTx"].pkScriptLocs()
        assert all(a == b for a, b in zip(pkScriptLocs, test["pkScriptLocs"]))

        for j, loc in enumerate(pkScriptLocs):
            wantPkScript = test["inTx"].txOut[j].pkScript
            gotPkScript = test["buf"][loc: loc+len(wantPkScript)]
            assert gotPkScript == wantPkScript


def test_TxOverflowErrors():
    """
    test_TxOverflowErrors performs tests to ensure deserializing transactions
    which are intentionally crafted to use large values for the variable number
    of inputs and outputs are handled properly.  This could otherwise potentially
    be used as an attack vector.
    """
    # Use protocol version 70001 and transaction version 1 specifically
    # here instead of the latest values because the test data is using
    # bytes encoded with those versions.
    pver = 70001

    tests = [
        (
            "too many inputs",
            ByteArray([
                0x00, 0x00, 0x00, 0x01,  # Version
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff,  # Varint for number of input transactions
            ]),
        ),

        # Transaction that claims to have ~uint64(0) outputs.
        (
            "too many outputs",
            ByteArray([
                0x00, 0x00, 0x00, 0x01,  # Version
                0x00,  # Varint for number of input transactions
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff,  # Varint for number of output transactions
            ]),
        ),

        # Transaction that has an input with a signature script that
        # claims to have ~uint64(0) length.
        (
            "sig script too long",
            ByteArray([
                0x00, 0x00, 0x00, 0x01,  # Version
                0x01,  # Varint for number of input transactions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Previous output hash
                0xff, 0xff, 0xff, 0xff,  # Prevous output index
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff,  # Varint for length of signature script
            ]),
        ),

        # Transaction that has an output with a public key script
        # that claims to have ~uint64(0) length.
        (
            "pubkey script too long",
            ByteArray([
                0x00, 0x00, 0x00, 0x01,  # Version
                0x01,  # Varint for number of input transactions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Previous output hash
                0xff, 0xff, 0xff, 0xff,  # Prevous output index
                0x00,                   # Varint for length of signature script
                0xff, 0xff, 0xff, 0xff,  # Sequence
                0x01,                                            # Varint for number of output transactions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Transaction amount
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff,  # Varint for length of public key script
            ]),
        ),
    ]

    for name, b in tests:
        with pytest.raises(DecredError):
            msgtx.MsgTx.btcDecode(b.copy(), pver, msgtx.BaseEncoding)

        with pytest.raises(DecredError):
            msgtx.MsgTx.deserialize(b)


def test_TxSerializeSizeStripped():
    """
    test_TxSerializeSizeStripped performs tests to ensure the serialize size for
    various transactions is accurate.
    """
    # Empty tx message.
    assert msgtx.MsgTx(version=1).serializeSizeStripped() == 10

    # Transcaction with an input and an output.
    assert multiTx.serializeSizeStripped() == 210

    # Transaction with an input which includes witness data, and
    # one output. Note that this uses SerializeSizeStripped which
    # excludes the additional bytes due to witness data encoding.
    assert multiWitnessTx.serializeSizeStripped() == 82


def test_TxWitnessSize():
    """
    test_TxWitnessSize performs tests to ensure that the serialized size for
    various types of transactions that include witness data is accurate.
    """
    assert multiWitnessTx.serializeSize() == 190


multiTx = msgtx.MsgTx(
    version=1,
    txIn=[
        msgtx.TxIn(
            previousOutPoint=msgtx.OutPoint(
                txHash=ByteArray(length=32),
                idx=0xffffffff,
            ),
            signatureScript=ByteArray("0431dc001b0162"),
            sequence=0xffffffff,
        ),
    ],
    txOut=[
        msgtx.TxOut(
            value=0x12a05f200,
            pkScript=ByteArray([
                0x41,  # OP_DATA_65
                0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                0xa6,  # 65-byte signature
                0xac,  # OP_CHECKSIG
            ]),
        ),
        msgtx.TxOut(
            value=0x5f5e100,
            pkScript=ByteArray([
                0x41,  # OP_DATA_65
                0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                0xa6,  # 65-byte signature
                0xac,  # OP_CHECKSIG
            ]),
        ),
    ],
    lockTime=0,
)

# multiTxEncoded is the wire encoded bytes for multiTx using protocol version
# 60002 and is used in the various tests.
multiTxEncoded = ByteArray([
    0x01, 0x00, 0x00, 0x00,  # Version
    0x01,  # Varint for number of input transactions
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Previous output hash
    0xff, 0xff, 0xff, 0xff,  # Prevous output index
    0x07,                                      # Varint for length of signature script
    0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62,  # Signature script
    0xff, 0xff, 0xff, 0xff,  # Sequence
    0x02,                                            # Varint for number of output transactions
    0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00,  # Transaction amount
    0x43,  # Varint for length of pk script
    0x41,  # OP_DATA_65
    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
    0xa6,                                            # 65-byte signature
    0xac,                                            # OP_CHECKSIG
    0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,  # Transaction amount
    0x43,  # Varint for length of pk script
    0x41,  # OP_DATA_65
    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
    0xa6,                    # 65-byte signature
    0xac,                    # OP_CHECKSIG
    0x00, 0x00, 0x00, 0x00,  # Lock time
])

multiTxPkScriptLocs = (63, 139)

multiWitnessTx = msgtx.MsgTx(
    version=1,
    txIn=[
        msgtx.TxIn(
            previousOutPoint=msgtx.OutPoint(
                txHash=ByteArray([
                    0xa5, 0x33, 0x52, 0xd5, 0x13, 0x57, 0x66, 0xf0,
                    0x30, 0x76, 0x59, 0x74, 0x18, 0x26, 0x3d, 0xa2,
                    0xd9, 0xc9, 0x58, 0x31, 0x59, 0x68, 0xfe, 0xa8,
                    0x23, 0x52, 0x94, 0x67, 0x48, 0x1f, 0xf9, 0xcd,
                ]),
                idx=19,
            ),
            signatureScript=ByteArray(),
            witness=[
                ByteArray([  # 70-byte signature
                    0x30, 0x43, 0x02, 0x1f, 0x4d, 0x23, 0x81, 0xdc,
                    0x97, 0xf1, 0x82, 0xab, 0xd8, 0x18, 0x5f, 0x51,
                    0x75, 0x30, 0x18, 0x52, 0x32, 0x12, 0xf5, 0xdd,
                    0xc0, 0x7c, 0xc4, 0xe6, 0x3a, 0x8d, 0xc0, 0x36,
                    0x58, 0xda, 0x19, 0x02, 0x20, 0x60, 0x8b, 0x5c,
                    0x4d, 0x92, 0xb8, 0x6b, 0x6d, 0xe7, 0xd7, 0x8e,
                    0xf2, 0x3a, 0x2f, 0xa7, 0x35, 0xbc, 0xb5, 0x9b,
                    0x91, 0x4a, 0x48, 0xb0, 0xe1, 0x87, 0xc5, 0xe7,
                    0x56, 0x9a, 0x18, 0x19, 0x70, 0x01,
                ]),
                ByteArray([  # 33-byte serialize pub key
                    0x03, 0x07, 0xea, 0xd0, 0x84, 0x80, 0x7e, 0xb7,
                    0x63, 0x46, 0xdf, 0x69, 0x77, 0x00, 0x0c, 0x89,
                    0x39, 0x2f, 0x45, 0xc7, 0x64, 0x25, 0xb2, 0x61,
                    0x81, 0xf5, 0x21, 0xd7, 0xf3, 0x70, 0x06, 0x6a,
                    0x8f,
                ]),
            ],
            sequence=0xffffffff,
        ),
    ],
    txOut=[
        msgtx.TxOut(
            value=395019,
            pkScript=ByteArray([  # p2wkh output
                0x00,  # Version 0 witness program
                0x14,  # OP_DATA_20
                0x9d, 0xda, 0xc6, 0xf3, 0x9d, 0x51, 0xe0, 0x39,
                0x8e, 0x53, 0x2a, 0x22, 0xc4, 0x1b, 0xa1, 0x89,
                0x40, 0x6a, 0x85, 0x23,  # 20-byte pub key hash
            ]),
        ),
    ],
)

multiWitnessTxEncoded = ByteArray([
    0x1, 0x0, 0x0, 0x0,  # Version
    msgtx.TxFlagMarker,  # Marker byte indicating 0 inputs, or a segwit encoded tx
    msgtx.WitnessFlag,   # Flag byte
    0x1,           # Varint for number of inputs
    0xa5, 0x33, 0x52, 0xd5, 0x13, 0x57, 0x66, 0xf0,
    0x30, 0x76, 0x59, 0x74, 0x18, 0x26, 0x3d, 0xa2,
    0xd9, 0xc9, 0x58, 0x31, 0x59, 0x68, 0xfe, 0xa8,
    0x23, 0x52, 0x94, 0x67, 0x48, 0x1f, 0xf9, 0xcd,  # Previous output hash
    0x13, 0x0, 0x0, 0x0,  # Little endian previous output index
    0x0,                     # No sig script (this is a witness input)
    0xff, 0xff, 0xff, 0xff,  # Sequence
    0x1,                                     # Varint for number of outputs
    0xb, 0x7, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0,  # Output amount
    0x16,  # Varint for length of pk script
    0x0,   # Version 0 witness program
    0x14,  # OP_DATA_20
    0x9d, 0xda, 0xc6, 0xf3, 0x9d, 0x51, 0xe0, 0x39,
    0x8e, 0x53, 0x2a, 0x22, 0xc4, 0x1b, 0xa1, 0x89,
    0x40, 0x6a, 0x85, 0x23,  # 20-byte pub key hash
    0x2,   # Two items on the witness stack
    0x46,  # 70 byte stack item
    0x30, 0x43, 0x2, 0x1f, 0x4d, 0x23, 0x81, 0xdc,
    0x97, 0xf1, 0x82, 0xab, 0xd8, 0x18, 0x5f, 0x51,
    0x75, 0x30, 0x18, 0x52, 0x32, 0x12, 0xf5, 0xdd,
    0xc0, 0x7c, 0xc4, 0xe6, 0x3a, 0x8d, 0xc0, 0x36,
    0x58, 0xda, 0x19, 0x2, 0x20, 0x60, 0x8b, 0x5c,
    0x4d, 0x92, 0xb8, 0x6b, 0x6d, 0xe7, 0xd7, 0x8e,
    0xf2, 0x3a, 0x2f, 0xa7, 0x35, 0xbc, 0xb5, 0x9b,
    0x91, 0x4a, 0x48, 0xb0, 0xe1, 0x87, 0xc5, 0xe7,
    0x56, 0x9a, 0x18, 0x19, 0x70, 0x1,
    0x21,  # 33 byte stack item
    0x3, 0x7, 0xea, 0xd0, 0x84, 0x80, 0x7e, 0xb7,
    0x63, 0x46, 0xdf, 0x69, 0x77, 0x0, 0xc, 0x89,
    0x39, 0x2f, 0x45, 0xc7, 0x64, 0x25, 0xb2, 0x61,
    0x81, 0xf5, 0x21, 0xd7, 0xf3, 0x70, 0x6, 0x6a,
    0x8f,
    0x0, 0x0, 0x0, 0x0,  # Lock time
])

multiWitnessTxPkScriptLocs = [58]
