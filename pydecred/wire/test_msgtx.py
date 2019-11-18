"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest
from tinydecred.pydecred.wire import msgtx
from tinydecred.util import helpers
from tinydecred.pydecred.wire import wire
from tinydecred.crypto.bytearray import ByteArray

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
        """ TestTxHash tests the ability to generate the hash of a transaction accurately. """
        # Hash of first transaction from block 113875.
        wantHash = reversed(ByteArray("4538fc1618badd058ee88fd020984451024858796be0a1ed111877f887e1bd53"))

        msgTx = msgtx.MsgTx.new()
        txIn = msgtx.TxIn(
            previousOutPoint = msgtx.OutPoint(
                txHash =  None,
                idx = 0xffffffff,
                tree =  msgtx.TxTreeRegular,
            ),
            sequence =        0xffffffff,
            valueIn =         5000000000,
            blockHeight =     0x3F3F3F3F,
            blockIndex =      0x2E2E2E2E,
            signatureScript = ByteArray([0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62]),
        )
        txOut = msgtx.TxOut(
            value =   5000000000,
            version = 0xf0f0,
            pkScript = ByteArray([
                0x41, # OP_DATA_65
                0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                0xa6, # 65-byte signature
                0xac, # OP_CHECKSIG
            ]),
        )
        msgTx.addTxIn(txIn)
        msgTx.addTxOut(txOut)
        msgTx.lockTime = 0
        msgTx.expiry = 0
        # Ensure the hash produced is expected.
        self.assertEqual(msgTx.hash(), wantHash)
            
    def test_tx_serialize_prefix(self):
        """
        TestTxSerializePrefix tests MsgTx serialize and deserialize.
        """
        noTx = msgtx.MsgTx.new()
        noTx.version = 1
        noTx.serType = wire.TxSerializeNoWitness
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x01, 0x00, # Version
            0x00,                   # Varint for number of input transactions
            0x00,                   # Varint for number of output transactions
            0x00, 0x00, 0x00, 0x00, # Lock time
            0x00, 0x00, 0x00, 0x00, # Expiry
        ])

        mtPrefix = msgtx.multiTxPrefix()
        tests = [
            # No transactions.
            (
                noTx,        # in           *MsgTx  Message to encode
                noTx,        # out          *MsgTx  Expected decoded message
                noTxEncoded, # buf          []byte  Serialized data
                [],        # pkScriptLocs []int   Expected output script locations
            ),
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
                    gotPkScript = testBuf[loc : loc+len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript)
    def test_tx_serialize_witness(self):
        """ TestTxSerializeWitness tests MsgTx serialize and deserialize."""
        noTx = msgtx.MsgTx.new()
        noTx.serType = wire.TxSerializeOnlyWitness
        noTx.version = 1
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x02, 0x00, # Version
            0x00, # Varint for number of input signatures
        ])
        # in           *MsgTx // Message to encode
        # out          *MsgTx // Expected decoded message
        # buf          []byte // Serialized data
        # pkScriptLocs []int  // Expected output script locations
        tests = [
            # No transactions.
            [
                noTx,
                noTx,
                noTxEncoded,
                [],
            ],

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
                    gotPkScript = testBuf[loc : loc+len(wantPkScript)]
                    self.assertEqual(gotPkScript, wantPkScript)
    def test_tx_serialize(self):
        """ TestTxSerialize tests MsgTx serialize and deserialize. """
        noTx = msgtx.MsgTx.new()
        noTx.version = 1
        noTxEncoded = ByteArray([
            0x01, 0x00, 0x00, 0x00, # Version
            0x00,                   # Varint for number of input transactions
            0x00,                   # Varint for number of output transactions
            0x00, 0x00, 0x00, 0x00, # Lock time
            0x00, 0x00, 0x00, 0x00, # Expiry
            0x00, # Varint for number of input signatures
        ])
        # in           *MsgTx // Message to encode
        # out          *MsgTx // Expected decoded message
        # buf          []byte // Serialized data
        # pkScriptLocs []int  // Expected output script locations
        tests = [
            # No transactions.
            [
                noTx,
                noTx,
                noTxEncoded,
                [],
            ],

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
                    gotPkScript = testBuf[loc : loc+len(wantPkScript)]
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
        tests = [
            # Transaction that claims to have ~uint64(0) inputs. [0]
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, # Varint for number of input transactions
                ]), pver, txVer,
            ),

            # Transaction that claims to have ~uint64(0) outputs. [1]
            (
                ByteArray([
                    0x01, 0x00, 0x00, 0x00, # Version
                    0x00, # Varint for number of input transactions
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, # Varint for number of output transactions
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
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
                    0xff, 0xff, 0xff, 0xff, # Previous output index
                    0x00,                   # Previous output tree
                    0x00,                   # Varint for length of signature script
                    0xff, 0xff, 0xff, 0xff, # Sequence
                    0x02,                                           # Varint for number of output transactions
                    0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, # Transaction amount
                    0x43, # Varint for length of pk script
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6,                                           # 65-byte signature
                    0xac,                                           # OP_CHECKSIG
                    0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, # Transaction amount
                    0x43, # Varint for length of pk script
                    0x41, # OP_DATA_65
                    0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
                    0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
                    0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
                    0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
                    0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
                    0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
                    0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
                    0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
                    0xa6,                   # 65-byte signature
                    0xac,                   # OP_CHECKSIG
                    0x00, 0x00, 0x00, 0x00, # Lock time
                    0x00, 0x00, 0x00, 0x00, # Expiry
                    0x01,                                                 # Varint for number of input signature
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, # Varint for sig script length (overflows)
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
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Previous output hash
                    0xff, 0xff, 0xff, 0xff, # Prevous output index
                    0x00,                   # Previous output tree
                    0x00,                   # Varint for length of signature script
                    0xff, 0xff, 0xff, 0xff, # Sequence
                    0x01,                                           # Varint for number of output transactions
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Transaction amount
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, # Varint for length of public key script
                ]), pver, txVer,
            ),
        ]

        for i, (buf, pver, version) in enumerate(tests):
            # Decode from wire format.
            with self.assertRaises(Exception, msg="test %i" % i):
                msgtx.MsgTx.btcDecode(buf, pver)
    def  test_tx_serialize_errors(self): # TestTxSerializeErrors(t *testing.T) {
        """
        TestTxSerializeErrors performs negative tests against wire encode and decode
        of MsgTx to confirm error paths work correctly.
        """
        # in       *MsgTx // Value to encode
        # buf      []byte // Serialized data
        # max      int    // Max size of fixed buffer to induce errors
        # writeErr error  // Expected write error
        # readErr  error  // Expected read error
        test = [
            # Force error in version.
            (msgtx.multiTx, msgtx.multiTxEncoded, 0),
            # Force error in number of transaction inputs.
            (msgtx.multiTx, msgtx.multiTxEncoded, 4),
            # Force error in transaction input previous block hash.
            (msgtx.multiTx, msgtx.multiTxEncoded, 5),
            # Force error in transaction input previous block output index.
            (msgtx.multiTx, msgtx.multiTxEncoded, 37),
            # Force error in transaction input previous block output tree.
            (msgtx.multiTx, msgtx.multiTxEncoded, 41),
            # Force error in transaction input sequence.
            (msgtx.multiTx, msgtx.multiTxEncoded, 42),
            # Force error in number of transaction outputs.
            (msgtx.multiTx, msgtx.multiTxEncoded, 46),
            # Force error in transaction output value.
            (msgtx.multiTx, msgtx.multiTxEncoded, 47),
            # Force error in transaction output version.
            (msgtx.multiTx, msgtx.multiTxEncoded, 55),
            # Force error in transaction output pk script length.
            (msgtx.multiTx, msgtx.multiTxEncoded, 57),
            # Force error in transaction output pk script.
            (msgtx.multiTx, msgtx.multiTxEncoded, 58),
            # Force error in transaction lock time.
            (msgtx.multiTx, msgtx.multiTxEncoded, 203),
            # Force error in transaction expiry.
            (msgtx.multiTx, msgtx.multiTxEncoded, 207),
            # Force error in transaction num sig varint.
            (msgtx.multiTx, msgtx.multiTxEncoded, 211),
            # Force error in transaction sig 0 ValueIn.
            (msgtx.multiTx, msgtx.multiTxEncoded, 212),
            # Force error in transaction sig 0 BlockHeight.
            (msgtx.multiTx, msgtx.multiTxEncoded, 220),
            # Force error in transaction sig 0 BlockIndex.
            (msgtx.multiTx, msgtx.multiTxEncoded, 224),
            # Force error in transaction sig 0 length.
            (msgtx.multiTx, msgtx.multiTxEncoded, 228),
            # Force error in transaction sig 0 signature script.
            (msgtx.multiTx, msgtx.multiTxEncoded, 229),
        ]
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
    def test_tx(self):
        """
        TestTx tests the MsgTx API.
        This test is substantially truncated compare to it's counterpart in go
        """
        # Ensure the command is expected value.
        wantCmd = "tx"
        msg = msgtx.MsgTx.new()
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
        pver = 1
        hexTx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0300f2052a01000000000017a914cbb08d6ca783b533b2c7d24a51fbca92d937bf9987000000000000000000000e6a0c1b000000b1bf47057791232500ac23fc0600000000001976a914b1eef3d1535a3868d11fa297c35f3deba978036088ac000000000000000001009e29260800000000000000ffffffff0800002f646372642f"
        buf = ByteArray(hexTx)
        tx = msgtx.MsgTx.btcDecode(buf, pver)
        print(repr(tx.cachedHash))
        print(repr(tx.serType))
        print(repr(tx.version))
        print(repr(tx.txIn))
        print(repr(tx.txOut))
        print(repr(tx.lockTime))
        print(repr(tx.expiry))
        v = sum(txout.value for txout in tx.txOut)
        print("total sent: %.2f" % (v*1e-8,))
        print(tx.txHex())
