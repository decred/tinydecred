"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import time
import unittest

from decred.crypto import rando
from decred.dcr.wire import msgtx, wire
from decred.util import helpers
from decred.util.encode import ByteArray


def newHash():
    return ByteArray(rando.generateSeed(32))


class TestMsgTx(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.prepareLogger("TestMsgTx")

    def test_tx_serialize_size(self):
        """
        TestTxSerializeSize performs tests to ensure the serialize size for various
        transactions is accurate.
        """
        # Empty tx message.
        noTx = msgtx.MsgTx.new()
        noTx.version = 1

        tests = [
            # No inputs or outpus.
            (noTx, 15),
            # Transaction with an input and an output.
            (msgtx.multiTx(), 236),
        ]

        for i, (txIn, size) in enumerate(tests):
            self.assertEqual(txIn.serializeSize(), size)

    def test_tx_hash(self):
        """
        TestTxHash tests the ability to generate the hash of a transaction accurately.
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
        self.assertTrue(msgTx.looksLikeCoinbase())
        # Ensure the hash produced is expected.
        self.assertEqual(msgTx.hash(), wantHash)

    def test_tx_serialize_prefix(self):
        """
        TestTxSerializePrefix tests MsgTx serialize and deserialize.
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

        mtPrefix = msgtx.multiTxPrefix()
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
                msgtx.multiTxPrefixEncoded(),
                msgtx.multiTxPkScriptLocs,
            ),
        ]

        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            self.assertEqual(len(buf), inTx.serializeSize())
            self.assertEqual(buf, testBuf)

            # Deserialize the transaction.
            tx = msgtx.MsgTx.deserialize(testBuf.copy())

            self.assertEqual(tx, out)

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()

            if pkScriptLocs is None:
                self.assertEqual(psl, pkScriptLocs)
            else:
                self.assertListEqual(psl, pkScriptLocs)
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.txOut[j].pkScript
                    gotPkScript = testBuf[loc : loc + len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript)

    def test_tx_serialize_witness(self):
        """
        TestTxSerializeWitness tests MsgTx serialize and deserialize.
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
                msgtx.multiTxWitness(),
                msgtx.multiTxWitness(),
                msgtx.multiTxWitnessEncoded(),
                [],
            ],
        ]
        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            self.assertEqual(len(buf), inTx.serializeSize())
            self.assertEqual(buf, testBuf)

            # Deserialize the transaction.
            tx = msgtx.MsgTx.deserialize(testBuf.copy())
            self.assertEqual(tx, out)

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()
            if pkScriptLocs is None:
                self.assertEqual(psl, pkScriptLocs)
            else:
                self.assertListEqual(psl, pkScriptLocs)
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.TxIn[j].pkScript
                    gotPkScript = testBuf[loc : loc + len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript)

    def test_tx_serialize(self):
        """
        TestTxSerialize tests MsgTx serialize and deserialize.
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
                msgtx.multiTx(),
                msgtx.multiTx(),
                msgtx.multiTxEncoded(),
                msgtx.multiTxPkScriptLocs,
            ],
        ]

        for i, (inTx, out, testBuf, pkScriptLocs) in enumerate(tests):
            # Serialize the transaction.
            buf = inTx.serialize()
            self.assertEqual(len(buf), inTx.serializeSize(), msg="buflen %i" % i)
            self.assertEqual(buf, testBuf, msg="buf contents %i" % i)

            # Deserialize the transaction.
            tx = msgtx.MsgTx.deserialize(testBuf.copy())

            self.assertEqual(tx, out, msg="txs %i" % i)

            # Ensure the public key script locations are accurate.
            psl = inTx.pkScriptLocs()
            if pkScriptLocs is None:
                self.assertEqual(psl, pkScriptLocs, msg="psl none %i" % i)
            else:
                self.assertListEqual(psl, pkScriptLocs, msg="psl %i" % i)
                for j, loc in enumerate(psl):
                    wantPkScript = inTx.txOut[j].pkScript
                    gotPkScript = testBuf[loc : loc + len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript, msg="scripts %i" % i)

    def test_tx_overflow_errors(self):
        """
        TestTxOverflowErrors performs tests to ensure deserializing transactions
        which are intentionally crafted to use large values for the variable number
        of inputs and outputs are handled properly.  This could otherwise potentially
        be used as an attack vector.
        """
        # Use protocol version 1 and transaction version 1 specifically
        # here instead of the latest values because the test data is using
        # bytes encoded with those versions.
        pver = 1
        txVer = 1
        # buf     []byte // Wire encoding
        # pver    uint32 // Protocol version for wire encoding
        # version int32  // Transaction version
        # err     error  // Expected error
        # fmt: off
        tests = [
            # Transaction that claims to have ~uint64(0) inputs. [0]
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                    0XFF, # Varint for number of input transactions
                ]), pver, txVer,
            ),

            # Transaction that claims to have ~uint64(0) outputs. [1]
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0x00, # Varint for number of input transactions
                    0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                    0XFF, # Varint for number of output transactions
                ]), pver, txVer,
            ),

            # Transaction that has an input with a signature script that [2]
            # claims to have ~uint64(0) length.
            (
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
                ]), pver, txVer,
            ),

            # Transaction that has an output with a public key script [3]
            # that claims to have ~uint64(0) length.
            (
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
                ]), pver, txVer,
            ),
        ]
        # fmt: on

        for i, (buf, pver, version) in enumerate(tests):
            # Decode from wire format.
            with self.assertRaises(Exception, msg="test %i" % i):
                msgtx.MsgTx.btcDecode(buf, pver)

    def test_tx_serialize_errors(self):
        """
        TestTxSerializeErrors performs negative tests against wire encode and decode
        of MsgTx to confirm error paths work correctly.
        """
        # in       *MsgTx // Value to encode
        # buf      []byte // Serialized data
        # max      int    // Max size of fixed buffer to induce errors
        # writeErr error  // Expected write error
        # readErr  error  // Expected read error
        # test = [
        #     # Force error in version.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 0),
        #     # Force error in number of transaction inputs.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 4),
        #     # Force error in transaction input previous block hash.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 5),
        #     # Force error in transaction input previous block output index.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 37),
        #     # Force error in transaction input previous block output tree.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 41),
        #     # Force error in transaction input sequence.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 42),
        #     # Force error in number of transaction outputs.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 46),
        #     # Force error in transaction output value.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 47),
        #     # Force error in transaction output version.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 55),
        #     # Force error in transaction output pk script length.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 57),
        #     # Force error in transaction output pk script.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 58),
        #     # Force error in transaction lock time.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 203),
        #     # Force error in transaction expiry.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 207),
        #     # Force error in transaction num sig varint.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 211),
        #     # Force error in transaction sig 0 ValueIn.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 212),
        #     # Force error in transaction sig 0 BlockHeight.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 220),
        #     # Force error in transaction sig 0 BlockIndex.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 224),
        #     # Force error in transaction sig 0 length.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 228),
        #     # Force error in transaction sig 0 signature script.
        #     (msgtx.multiTx, msgtx.multiTxEncoded, 229),
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
        #
        #   # Deserialize the transaction.
        #   var tx MsgTx
        #   r := newFixedReader(test.max, test.buf)
        #   err = tx.Deserialize(r)
        #   if err != test.readErr {
        #       t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
        #           i, err, test.readErr)
        #       continue

    def test_tx(self):
        """
        Substantially truncated compared to its counterpart in Go.
        """
        msg = msgtx.MsgTx.new()

        # Check the tx id.
        self.assertEqual(
            msg.id(), "bfc0e650ad0cc0dd5fa88b6bc84beb5ea4a675b4353671532796171ed319341b"
        )

        # Check the blob.
        # fmt: off
        self.assertEqual(
            msgtx.MsgTx.blob(msg),
            ByteArray(
                [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ),
        )
        # fmt: on

        # Ensure the command is expected value.
        wantCmd = "tx"
        self.assertEqual(msg.command(), wantCmd)

        # Ensure max payload is expected value for latest protocol version.
        # Num addresses (varInt) + max allowed addresses.
        wantPayload = 1310720
        maxPayload = msg.maxPayloadLength(wire.ProtocolVersion)
        self.assertEqual(maxPayload, wantPayload)

        # Ensure max payload is expected value for protocol version 3.
        wantPayload = 1000000
        maxPayload = msg.maxPayloadLength(3)
        self.assertEqual(wantPayload, maxPayload)

    def test_tx_from_hex(self):
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

        self.assertEqual(tx.serType, reTx.serType)
        self.assertEqual(tx.version, reTx.version)
        self.assertEqual(tx.lockTime, reTx.lockTime)
        self.assertEqual(tx.expiry, reTx.expiry)

        for i, txIn in enumerate(tx.txIn):
            reTxIn = reTx.txIn[i]
            self.assertEqual(txIn.previousOutPoint.hash, reTxIn.previousOutPoint.hash)
            self.assertEqual(txIn.previousOutPoint.index, reTxIn.previousOutPoint.index)
            self.assertEqual(txIn.previousOutPoint.tree, reTxIn.previousOutPoint.tree)
            self.assertEqual(txIn.sequence, reTxIn.sequence)
            self.assertEqual(txIn.valueIn, reTxIn.valueIn)
            self.assertEqual(txIn.blockHeight, reTxIn.blockHeight)
            self.assertEqual(txIn.blockIndex, reTxIn.blockIndex)
            self.assertEqual(txIn.signatureScript, reTxIn.signatureScript)

        for i, txOut in enumerate(tx.txOut):
            reTxOut = reTx.txOut[i]
            self.assertEqual(txOut.value, reTxOut.value)
            self.assertEqual(txOut.version, reTxOut.version)
            self.assertEqual(txOut.pkScript, reTxOut.pkScript)

    def test_read_tx_in_prefix(self):
        self.assertRaises(
            ValueError,
            msgtx.readTxInPrefix,
            None,
            None,
            wire.TxSerializeOnlyWitness,
            None,
            None,
        )

    def test_read_script(self):
        self.assertRaises(
            ValueError,
            msgtx.readScript,
            ByteArray([0xFC]),
            wire.ProtocolVersion,
            0,
            "Field",
        )

    def test_outpoint_txid(self):
        outp = msgtx.OutPoint(txHash=None, idx=0, tree=0)
        self.assertEqual(
            outp.txid(),
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
