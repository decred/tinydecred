"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import time

import pytest

from decred import DecredError
from decred.crypto import rando
from decred.dcr.wire import msgtx, wire
from decred.util.encode import ByteArray


LOGGER_ID = "TestMsgTx"


def newHash():
    return ByteArray(rando.generateSeed(32))


# fmt: off

def multiTxPrefix():
    """
    multiTxPrefix is a MsgTx prefix with an input and output and used in various tests.
    """
    return msgtx.MsgTx(
        cachedHash=None,
        serType=wire.TxSerializeNoWitness,
        version=1,
        txIn=[
            msgtx.TxIn(
                previousOutPoint=msgtx.OutPoint(
                    txHash=None,
                    idx=0xFFFFFFFF,
                    tree=msgtx.TxTreeRegular,
                ),
                sequence=0xFFFFFFFF,
            ),
        ],
        txOut=[
            msgtx.TxOut(
                value=0x12A05F200,
                version=0xABAB,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
            msgtx.TxOut(
                value=0x5F5E100,
                version=0xBCBC,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
        ],
        lockTime=0,
        expiry=0,
    )


def multiTxPrefixEncoded():
    """
    multiTxPrefixEncoded is the wire encoded bytes for multiTx using protocol
    version 1 and is used in the various tests.
    """
    return ByteArray([
        0x01, 0x00, 0x01, 0x00, # Version [0]
        0x01,                           # Varint for number of input transactions [4]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # [5]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
        0XFF, 0XFF, 0XFF, 0XFF,         # Previous output index [37]
        0x00,                           # Previous output tree [41]
        0XFF, 0XFF, 0XFF, 0XFF,         # Sequence [43]
        0x02,                           # Varint for number of output transactions [47]
        0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, # Transaction amount [48]
        0xAB, 0xAB,                     # Script version
        0x43,                           # Varint for length of pk script [56]
        0x41,                           # OP_DATA_65 [57]
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                                           # 65-byte signature
        0xAC,                                           # OP_CHECKSIG
        0x00, 0xe1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount [124]
        0xBC, 0xBC,                     # Script version
        0x43,                           # Varint for length of pk script [132]
        0x41,                           # OP_DATA_65
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                           # 65-byte signature
        0xAC,                           # OP_CHECKSIG
        0x00, 0x00, 0x00, 0x00,         # Lock time [198]
        0x00, 0x00, 0x00, 0x00,         # Expiry [202]
    ])


multiTxPkScriptLocs = [58, 136]


def multiTxWitness():
    """
    multiTxWitness is a MsgTx witness with only input witness.
    """
    return msgtx.MsgTx(
        cachedHash=None,
        serType=wire.TxSerializeOnlyWitness,
        version=1,
        txIn=[
            msgtx.TxIn(
                previousOutPoint=None,
                sequence=0,
                valueIn=0x1212121212121212,
                blockHeight=0x15151515,
                blockIndex=0x34343434,
                signatureScript=ByteArray([
                    0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62
                ]),
            ),
        ],
        txOut=[],
        lockTime=0,
        expiry=0,
    )


def multiTxWitnessEncoded():
    return ByteArray([
        0x01, 0x00, 0x02, 0x00, # Version
        0x01,                           # Varint for number of input signature
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, # ValueIn
        0x15, 0x15, 0x15, 0x15,         # BlockHeight
        0x34, 0x34, 0x34, 0x34,         # BlockIndex
        0x07,                           # Varint for length of signature script
        0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62, # Signature script
    ])


def multiTx():
    """
    multiTx is a MsgTx with an input and output and used in various tests.
    """
    return msgtx.MsgTx(
        cachedHash=None,
        serType=wire.TxSerializeFull,
        version=1,
        txIn=[
            msgtx.TxIn(
                previousOutPoint=msgtx.OutPoint(
                    txHash=None,
                    idx=0xFFFFFFFF,
                    tree=0,
                ),
                sequence=0xFFFFFFFF,
                valueIn=0x1212121212121212,
                blockHeight=0x15151515,
                blockIndex=0x34343434,
                signatureScript=ByteArray([
                    0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62
                ]),
            ),
        ],
        txOut=[
            msgtx.TxOut(
                value=0x12A05F200,
                version=0xABAB,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
            msgtx.TxOut(
                value=0x5F5E100,
                version=0xBCBC,
                pkScript=ByteArray([
                    0x41, # OP_DATA_65
                    0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                    0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                    0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                    0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                    0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                    0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                    0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                    0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                    0xA6, # 65-byte signature
                    0xAC, # OP_CHECKSIG
                ]),
            ),
        ],
        lockTime=0,
        expiry=0,
    )


def multiTxEncoded():
    """
    multiTxEncoded is the wire encoded bytes for multiTx using protocol version
    0 and is used in the various tests.
    """
    return ByteArray([
        0x01, 0x00, 0x00, 0x00, # Version [0]
        0x01,                           # Varint for number of input transactions [4]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # [5]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
        0XFF, 0XFF, 0XFF, 0XFF,         # Previous output index [37]
        0x00,                           # Previous output tree [41]
        0XFF, 0XFF, 0XFF, 0XFF,         # Sequence [42]
        0x02,                           # Varint for number of output transactions [46]
        0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, # Transaction amount [47]
        0xAB, 0xAB,                     # Script version [55]
        0x43,                           # Varint for length of pk script [57]
        0x41,                           # OP_DATA_65 [58]
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                                           # 65-byte pubkey
        0xAC,                                           # OP_CHECKSIG
        0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount [123]
        0xBC, 0xBC,                     # Script version [134]
        0x43,                           # Varint for length of pk script [136]
        0x41,                           # OP_DATA_65
        0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
        0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
        0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
        0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
        0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
        0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
        0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
        0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
        0xA6,                           # 65-byte signature
        0xAC,                           # OP_CHECKSIG
        0x00, 0x00, 0x00, 0x00,         # Lock time [203]
        0x00, 0x00, 0x00, 0x00,         # Expiry [207]
        0x01,                           # Varint for number of input signature [211]
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, # ValueIn [212]
        0x15, 0x15, 0x15, 0x15,         # BlockHeight [220]
        0x34, 0x34, 0x34, 0x34,         # BlockIndex [224]
        0x07,                           # Varint for length of signature script [228]
        0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62, # Signature script [229]
    ])

# fmt: off


class TestMsgTx:
    def test_tx_serialize_size(self, prepareLogger):
        """
        test_tx_serialize_size performs tests to ensure the serialize size for
        various transactions is accurate.
        """
        # Empty tx message.
        noTx = msgtx.MsgTx.new()
        noTx.version = 1

        tests = [
            # No inputs or outpus.
            (noTx, 15),
            # Transaction with an input and an output.
            (multiTx(), 236),
        ]

        for i, (txIn, size) in enumerate(tests):
            assert txIn.serializeSize() == size

    def test_tx_hash(self, prepareLogger):
        """
        test_tx_hash tests the ability to generate the hash of a transaction
        accurately.
        """
        # Hash of first transaction from block 113875.
        wantHash = reversed(
            ByteArray(
                "4538fc1618badd058ee88fd020984451024858796be0a1ed111877f887e1bd53"
            )
        )

        msgTx = msgtx.MsgTx.new()
        txIn = msgtx.TxIn(
            previousOutPoint=msgtx.OutPoint(
                txHash=None, idx=0xFFFFFFFF, tree=msgtx.TxTreeRegular,
            ),
            sequence=0xFFFFFFFF,
            valueIn=5000000000,
            blockHeight=0x3F3F3F3F,
            blockIndex=0x2E2E2E2E,
            signatureScript=ByteArray([0x04, 0x31, 0xDC, 0x00, 0x1B, 0x01, 0x62]),
        )
        # fmt: off
        txOut = msgtx.TxOut(
            value=5000000000,
            version=0xF0F0,
            pkScript=ByteArray([
                0x41, # OP_DATA_65
                0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                0xA6, # 65-byte signature
                0xAC, # OP_CHECKSIG
            ]),
        )
        # fmt: on
        msgTx.addTxIn(txIn)
        msgTx.addTxOut(txOut)
        msgTx.lockTime = 0
        msgTx.expiry = 0
        # Check that this is the very first tx in the chain.
        assert msgTx.looksLikeCoinbase()
        # Ensure the hash produced is expected.
        assert msgTx.hash() == wantHash

    def test_tx_serialize_prefix(self, prepareLogger):
        """
        test_tx_serialize_prefix tests MsgTx serialize and deserialize of
        prefix-only transactions.
        """
        noTx = msgtx.MsgTx.new()
        noTx.version = 1
        noTx.serType = wire.TxSerializeNoWitness
        # fmt: off
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x01, 0x00, # Version
            0x00,                   # Varint for number of input transactions
            0x00,                   # Varint for number of output transactions
            0x00, 0x00, 0x00, 0x00, # Lock time
            0x00, 0x00, 0x00, 0x00, # Expiry
        ])
        # fmt: on

        mtPrefix = multiTxPrefix()
        tests = [
            # fmt: off
            # No transactions.
            (
                noTx,         # in           *MsgTx  Message to encode
                noTx,         # out          *MsgTx  Expected decoded message
                noTxEncoded,  # buf          []byte  Serialized data
                [],           # pkScriptLocs []int   Expected output script locations
            ),
            # fmt: on
            # Multiple transactions.
            (
                mtPrefix,
                mtPrefix,
                multiTxPrefixEncoded(),
                multiTxPkScriptLocs,
            ),
        ]

        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            assert len(buf) == inTx.serializeSize()
            assert buf == testBuf

            # Deserialize the transaction.
            tx = msgtx.MsgTx.deserialize(testBuf.copy())
            assert tx == out

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()

            if pkScriptLocs is None:
                assert psl == pkScriptLocs
            else:
                assert psl == pkScriptLocs
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.txOut[j].pkScript
                    gotPkScript = testBuf[loc : loc + len(wantPkScript)]
                    assert gotPkScript == wantPkScript

    def test_tx_serialize_witness(self, prepareLogger):
        """
        test_tx_serialize_witness tests MsgTx serialize and deserialize of
        witness-only transactions.
        """
        noTx = msgtx.MsgTx.new()
        noTx.serType = wire.TxSerializeOnlyWitness
        noTx.version = 1
        # fmt: off
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x02, 0x00, # Version
            0x00, # Varint for number of input signatures
        ])
        # fmt: on
        # in           *MsgTx // Message to encode
        # out          *MsgTx // Expected decoded message
        # buf          []byte // Serialized data
        # pkScriptLocs []int  // Expected output script locations
        tests = [
            # No transactions.
            [noTx, noTx, noTxEncoded, []],
            # Multiple transactions.
            [
                multiTxWitness(),
                multiTxWitness(),
                multiTxWitnessEncoded(),
                [],
            ],
        ]
        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            assert len(buf) == inTx.serializeSize()
            assert buf == testBuf

            # Deserialize the transaction.
            tx = msgtx.MsgTx.deserialize(testBuf.copy())
            assert tx == out

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()
            if pkScriptLocs is None:
                assert psl == pkScriptLocs
            else:
                assert psl == pkScriptLocs
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.TxIn[j].pkScript
                    gotPkScript = testBuf[loc : loc + len(wantPkScript)]
                    assert gotPkScript == wantPkScript

    def test_tx_serialize(self, prepareLogger):
        """
        test_tx_serialize tests MsgTx serialize and deserialize.
        """
        noTx = msgtx.MsgTx.new()
        noTx.version = 1
        # fmt: off
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x00, 0x00, # Version
            0x00,                   # Varint for number of input transactions
            0x00,                   # Varint for number of output transactions
            0x00, 0x00, 0x00, 0x00, # Lock time
            0x00, 0x00, 0x00, 0x00, # Expiry
            0x00, # Varint for number of input signatures
        ])
        # fmt: on
        # in           *MsgTx // Message to encode
        # out          *MsgTx // Expected decoded message
        # buf          []byte // Serialized data
        # pkScriptLocs []int  // Expected output script locations
        tests = [
            # No transactions.
            [noTx, noTx, noTxEncoded, []],
            # Multiple transactions.
            [
                multiTx(),
                multiTx(),
                multiTxEncoded(),
                multiTxPkScriptLocs,
            ],
        ]

        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            assert len(buf) == inTx.serializeSize(), f"buflen {i}"
            assert buf == testBuf, f"buf contents {i}"

            # Deserialize the transaction.
            tx = msgtx.MsgTx.deserialize(testBuf.copy())
            assert tx == out, f"txs {i}"

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()
            if pkScriptLocs is None:
                assert psl == pkScriptLocs, f"psl none {i}"
            else:
                assert psl == pkScriptLocs, f"psl {i}"
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.txOut[j].pkScript
                    gotPkScript = testBuf[loc : loc + len(wantPkScript)]
                    assert gotPkScript == wantPkScript, f"scripts {i}"

    def test_tx_overflow_errors(self, prepareLogger):
        """
        test_tx_overflow_errors performs tests to ensure deserializing
        transactions which are intentionally crafted to use large values for
        the variable number of inputs and outputs are handled properly.  This
        could otherwise potentially be used as an attack vector.
        """
        # Use protocol version 1 and transaction version 1 specifically
        # here instead of the latest values because the test data is using
        # bytes encoded with those versions.
        pver = 1
        # fmt: off
        tests = [
            # Transaction that claims to have ~uint64(0) inputs. [0]
            ByteArray([
                0x01, 0x00, 0x00, 0x00, # Version
                0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                0XFF, # Varint for number of input transactions
            ]),

            # Transaction that claims to have ~uint64(0) outputs. [1]
            ByteArray([
                0x01, 0x00, 0x00, 0x00, # Version
                0x00, # Varint for number of input transactions
                0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                0XFF, # Varint for number of output transactions
            ]),

            # Transaction that has an input with a signature script that [2]
            # claims to have ~uint64(0) length.
            ByteArray([
                0x01, 0x00, 0x00, 0x00, # Version
                0x01, # Varint for number of input transactions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        # Previous output hash
                0XFF, 0XFF, 0XFF, 0XFF, # Previous output index
                0x00,                   # Previous output tree
                0x00,                   # Varint for length of signature script
                0XFF, 0XFF, 0XFF, 0XFF, # Sequence
                0x02,                   # Varint for number of output transactions
                0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, # Transaction amount
                0x43, # Varint for length of pk script
                0x41, # OP_DATA_65
                0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                0xA6,                                           # 65-byte signature
                0xAC,                                           # OP_CHECKSIG
                0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount
                0x43, # Varint for length of pk script
                0x41, # OP_DATA_65
                0X04, 0XD6, 0X4B, 0XDF, 0XD0, 0X9E, 0XB1, 0XC5,
                0XFE, 0X29, 0X5A, 0XBD, 0XEB, 0X1D, 0XCA, 0X42,
                0X81, 0XBE, 0X98, 0X8E, 0X2D, 0XA0, 0XB6, 0XC1,
                0XC6, 0XA5, 0X9D, 0XC2, 0X26, 0XC2, 0X86, 0X24,
                0XE1, 0X81, 0X75, 0XE8, 0X51, 0XC9, 0X6B, 0X97,
                0X3D, 0X81, 0XB0, 0X1C, 0XC3, 0X1F, 0X04, 0X78,
                0X34, 0XBC, 0X06, 0XD6, 0XD6, 0XED, 0XF6, 0X20,
                0XD1, 0X84, 0X24, 0X1A, 0X6A, 0XED, 0X8B, 0X63,
                0xA6,                   # 65-byte signature
                0xAC,                   # OP_CHECKSIG
                0x00, 0x00, 0x00, 0x00, # Lock time
                0x00, 0x00, 0x00, 0x00, # Expiry
                0x01,                   # Varint for number of input signature
                0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                                        # Varint for sig script length (overflows)
            ]),

            # Transaction that has an output with a public key script [3]
            # that claims to have ~uint64(0) length.
            ByteArray([
                0x01, 0x00, 0x00, 0x00, # Version
                0x01, # Varint for number of input transactions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        # Previous output hash
                0XFF, 0XFF, 0XFF, 0XFF, # Prevous output index
                0x00,                   # Previous output tree
                0x00,                   # Varint for length of signature script
                0XFF, 0XFF, 0XFF, 0XFF, # Sequence
                0x01,                   # Varint for number of output transactions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Transaction amount
                0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                0xFF, # Varint for length of public key script
            ]),
        ]
        # fmt: on

        for buf in tests:
            # Decode from wire format.
            with pytest.raises(DecredError):
                msgtx.MsgTx.btcDecode(buf, pver)

    def test_tx_serialize_errors(self, prepareLogger):
        """
        test_tx_serialize_errors performs negative tests against wire encode
        and decode of MsgTx to confirm error paths work correctly.
        """
        # in       *MsgTx // Value to encode
        # buf      []byte // Serialized data
        # max      int    // Max size of fixed buffer to induce errors
        # writeErr error  // Expected write error
        # readErr  error  // Expected read error
        # test = [
        #     # Force error in version.
        #     (multiTx, multiTxEncoded, 0),
        #     # Force error in number of transaction inputs.
        #     (multiTx, multiTxEncoded, 4),
        #     # Force error in transaction input previous block hash.
        #     (multiTx, multiTxEncoded, 5),
        #     # Force error in transaction input previous block output index.
        #     (multiTx, multiTxEncoded, 37),
        #     # Force error in transaction input previous block output tree.
        #     (multiTx, multiTxEncoded, 41),
        #     # Force error in transaction input sequence.
        #     (multiTx, multiTxEncoded, 42),
        #     # Force error in number of transaction outputs.
        #     (multiTx, multiTxEncoded, 46),
        #     # Force error in transaction output value.
        #     (multiTx, multiTxEncoded, 47),
        #     # Force error in transaction output version.
        #     (multiTx, multiTxEncoded, 55),
        #     # Force error in transaction output pk script length.
        #     (multiTx, multiTxEncoded, 57),
        #     # Force error in transaction output pk script.
        #     (multiTx, multiTxEncoded, 58),
        #     # Force error in transaction lock time.
        #     (multiTx, multiTxEncoded, 203),
        #     # Force error in transaction expiry.
        #     (multiTx, multiTxEncoded, 207),
        #     # Force error in transaction num sig varint.
        #     (multiTx, multiTxEncoded, 211),
        #     # Force error in transaction sig 0 ValueIn.
        #     (multiTx, multiTxEncoded, 212),
        #     # Force error in transaction sig 0 BlockHeight.
        #     (multiTx, multiTxEncoded, 220),
        #     # Force error in transaction sig 0 BlockIndex.
        #     (multiTx, multiTxEncoded, 224),
        #     # Force error in transaction sig 0 length.
        #     (multiTx, multiTxEncoded, 228),
        #     # Force error in transaction sig 0 signature script.
        #     (multiTx, multiTxEncoded, 229),
        # ]
        # TO DO: Re-implement this test?
        # for i, (inTx, txBuf, mx) in enumerate(tests):
        #   # Serialize the transaction.
        #   w := newFixedWriter(test.max)
        #   err := test.in.Serialize(w)
        #   if err != test.writeErr {
        #       t.Errorf("Serialize #%d wrong error got: %v, want: %v",
        #           i, err, test.writeErr)
        #       continue
        #   }

        #   # Deserialize the transaction.
        #   var tx MsgTx
        #   r := newFixedReader(test.max, test.buf)
        #   err = tx.Deserialize(r)
        #   if err != test.readErr {
        #       t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
        #           i, err, test.readErr)
        #       continue

    def test_tx(self, prepareLogger):
        """
        Substantially truncated compared to its counterpart in Go.
        """
        msg = msgtx.MsgTx.new()

        # Check the tx id.
        assert msg.id() == (
            "bfc0e650ad0cc0dd5fa88b6bc84beb5ea4a675b4353671532796171ed319341b"
        )

        # Check the blob.
        # fmt: off
        assert msgtx.MsgTx.blob(msg) == ByteArray([
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ])
        # fmt: on

        # Ensure the command is expected value.
        assert msg.command() == "tx"

        # Ensure max payload is expected value for latest protocol version.
        # Num addresses (varInt) + max allowed addresses.
        wantPayload = 1310720
        maxPayload = msg.maxPayloadLength(wire.ProtocolVersion)
        assert maxPayload == wantPayload

        # Ensure max payload is expected value for protocol version 3.
        wantPayload = 1000000
        maxPayload = msg.maxPayloadLength(3)
        assert wantPayload == maxPayload

    def test_tx_from_hex(self, prepareLogger):
        tx = msgtx.MsgTx(
            cachedHash=None,
            serType=0,
            version=123,
            txIn=[
                msgtx.TxIn(
                    previousOutPoint=msgtx.OutPoint(txHash=newHash(), idx=5, tree=1),
                    sequence=msgtx.MaxTxInSequenceNum,
                    valueIn=500,
                    blockHeight=111,
                    blockIndex=12,
                    signatureScript=newHash(),
                ),
            ],
            txOut=[
                msgtx.TxOut(value=321, pkScript=newHash(), version=0),
                msgtx.TxOut(value=654, pkScript=newHash(), version=0),
                msgtx.TxOut(value=987, pkScript=newHash(), version=0),
            ],
            lockTime=int(time.time()),
            expiry=int(time.time()) + 86400,
        )

        b = tx.serialize()
        reTx = msgtx.MsgTx.unblob(b)

        assert tx.serType == reTx.serType
        assert tx.version == reTx.version
        assert tx.lockTime == reTx.lockTime
        assert tx.expiry == reTx.expiry

        for i, txIn in enumerate(tx.txIn):
            reTxIn = reTx.txIn[i]
            assert txIn.previousOutPoint.hash == reTxIn.previousOutPoint.hash
            assert txIn.previousOutPoint.index == reTxIn.previousOutPoint.index
            assert txIn.previousOutPoint.tree == reTxIn.previousOutPoint.tree
            assert txIn.sequence == reTxIn.sequence
            assert txIn.valueIn == reTxIn.valueIn
            assert txIn.blockHeight == reTxIn.blockHeight
            assert txIn.blockIndex == reTxIn.blockIndex
            assert txIn.signatureScript == reTxIn.signatureScript

        for i, txOut in enumerate(tx.txOut):
            reTxOut = reTx.txOut[i]
            assert txOut.value == reTxOut.value
            assert txOut.version == reTxOut.version
            assert txOut.pkScript == reTxOut.pkScript

    def test_read_tx_in_prefix(self, prepareLogger):
        with pytest.raises(DecredError):
            msgtx.readTxInPrefix(
                None,
                None,
                wire.TxSerializeOnlyWitness,
                None,
                None,
            )

    def test_read_script(self, prepareLogger):
        with pytest.raises(DecredError):
            msgtx.readScript(
                ByteArray([0xFC]),
                wire.ProtocolVersion,
                0,
                "Field",
            )

    def test_outpoint_txid(self, prepareLogger):
        outp = msgtx.OutPoint(txHash=None, idx=0, tree=0)
        assert outp.txid() == (
            "0000000000000000000000000000000000000000000000000000000000000000"
        )

    def test_decodeWitness_errors(self, prepareLogger):
        tx = msgtx.MsgTx.new()
        # Too many input transactions.
        with pytest.raises(DecredError):
            tx.decodeWitness(ByteArray([0xFE, 0xFF, 0xFF, 0xFF]), 1, False)
        # Number of signature scripts different from number of TxIns.
        with pytest.raises(DecredError):
            tx.decodeWitness(ByteArray([0x01]), 1, True)
