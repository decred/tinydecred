"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

from base58 import b58decode
import json
import os
from tempfile import TemporaryDirectory
import time
import unittest


from decred.crypto import crypto, opcode, rando
from decred.crypto.secp256k1 import curve as Curve
from decred.dcr import account, txscript, vsp
from decred.dcr.calc import SubsidyCache
from decred.dcr.nets import mainnet, testnet
from decred.dcr.wire import msgtx, wire
from decred.util import database
from decred.util.encode import ByteArray
from decred.wallet.accounts import createAccount


testSeed = ByteArray(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
).b


def newHash():
    return ByteArray(rando.generateSeed(32))


def parseShortForm(asm):
    b = ByteArray(b"")
    for token in asm.split():
        if token.startswith("0x"):
            b += ByteArray(token[2:])
        else:
            longToken = "OP_" + token
            if hasattr(opcode, longToken):
                b += ByteArray(getattr(opcode, longToken))
            else:
                raise Exception("unknown token %s" % token)
    return b


class scriptClassTest:
    def __init__(self, name=None, script=None, scriptClass=None, subClass=None):
        self.name = name
        self.script = script
        self.scriptClass = scriptClass
        self.subClass = subClass


def scriptClassTests():
    return [
        scriptClassTest(
            name="Pay Pubkey",
            script="DATA_65 0x0411db93e1dcdb8a016b49840f8c53bc1eb68a382e"
            + "97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e16"
            + "0bfa9b8b64f9d4c03f999b8643f656b412a3 CHECKSIG",
            scriptClass=txscript.PubKeyTy,
        ),
        # tx 599e47a8114fe098103663029548811d2651991b62397e057f0c863c2bc9f9ea
        scriptClassTest(
            name="Pay PubkeyHash",
            script="DUP HASH160 DATA_20 0x660d4ef3a743e3e696ad990364e555"
            + "c271ad504b EQUALVERIFY CHECKSIG",
            scriptClass=txscript.PubKeyHashTy,
        ),
        # part of tx 6d36bc17e947ce00bb6f12f8e7a56a1585c5a36188ffa2b05e10b4743273a74b
        # codeseparator parts have been elided. (bitcoin core's checks for
        # multisig type doesn't have codesep either).
        scriptClassTest(
            name="multisig",
            script="1 DATA_33 0x0232abdc893e7f0631364d7fd01cb33d24da4"
            + "5329a00357b3a7886211ab414d55a 1 CHECKMULTISIG",
            scriptClass=txscript.MultiSigTy,
        ),
        # tx e5779b9e78f9650debc2893fd9636d827b26b4ddfa6a8172fe8708c924f5c39d
        scriptClassTest(
            name="P2SH",
            script="HASH160 DATA_20 0x433ec2ac1ffa1b7b7d027f564529c57197f"
            + "9ae88 EQUAL",
            scriptClass=txscript.ScriptHashTy,
        ),
        scriptClassTest(
            name="Stake Submission P2SH",
            script="SSTX HASH160 DATA_20 0x433ec2ac1ffa1b7b7d027f564529"
            + "c57197f9ae88 EQUAL",
            scriptClass=txscript.StakeSubmissionTy,
            subClass=txscript.ScriptHashTy,
        ),
        scriptClassTest(
            name="Stake Submission Generation P2SH",
            script="SSGEN HASH160 DATA_20 0x433ec2ac1ffa1b7b7d027f564529"
            + "c57197f9ae88 EQUAL",
            scriptClass=txscript.StakeGenTy,
            subClass=txscript.ScriptHashTy,
        ),
        scriptClassTest(
            name="Stake Submission Revocation P2SH",
            script="SSRTX HASH160 DATA_20 0x433ec2ac1ffa1b7b7d027f564529"
            + "c57197f9ae88 EQUAL",
            scriptClass=txscript.StakeRevocationTy,
            subClass=txscript.ScriptHashTy,
        ),
        scriptClassTest(
            name="Stake Submission Change P2SH",
            script="SSTXCHANGE HASH160 DATA_20 0x433ec2ac1ffa1b7b7d027f5"
            + "64529c57197f9ae88 EQUAL",
            scriptClass=txscript.StakeSubChangeTy,
            subClass=txscript.ScriptHashTy,
        ),
        scriptClassTest(
            # Nulldata with no data at all.
            name="nulldata no data",
            script="RETURN",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Nulldata with single zero push.
            name="nulldata zero",
            script="RETURN 0",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Nulldata with small integer push.
            name="nulldata small int",
            script="RETURN 1",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Nulldata with max small integer push.
            name="nulldata max small int",
            script="RETURN 16",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Nulldata with small data push.
            name="nulldata small data",
            script="RETURN DATA_8 0x046708afdb0fe554",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Canonical nulldata with 60-byte data push.
            name="canonical nulldata 60-byte push",
            script="RETURN 0x3c 0x046708afdb0fe5548271967f1a67130b7105cd"
            + "6a828e03909a67962e0ea1f61deb649f6bc3f4cef3046708afdb"
            + "0fe5548271967f1a67130b7105cd6a",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Non-canonical nulldata with 60-byte data push.
            name="non-canonical nulldata 60-byte push",
            script="RETURN PUSHDATA1 0x3c 0x046708afdb0fe5548271967f1a67"
            + "130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3"
            + "046708afdb0fe5548271967f1a67130b7105cd6a",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Nulldata with max allowed data to be considered standard.
            name="nulldata max standard push",
            script="RETURN PUSHDATA1 0x50 0x046708afdb0fe5548271967f1a67"
            + "130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3"
            + "046708afdb0fe5548271967f1a67130b7105cd6a828e03909a67"
            + "962e0ea1f61deb649f6bc3f4cef3",
            scriptClass=txscript.NullDataTy,
        ),
        scriptClassTest(
            # Nulldata with more than max allowed data to be considered
            # standard (so therefore nonstandard)
            name="nulldata exceed max standard push",
            script="RETURN PUSHDATA2 0x1801 0x046708afdb0fe5548271967f1a670"
            + "46708afdb0fe5548271967f1a67046708afdb0fe5548271967f1a670467"
            + "08afdb0fe5548271967f1a67046708afdb0fe5548271967f1a67046708a"
            + "fdb0fe5548271967f1a67046708afdb0fe5548271967f1a67046708afdb"
            + "0fe5548271967f1a67046708afdb0fe5548271967f1a67046708afdb0fe"
            + "5548271967f1a67",
            scriptClass=txscript.NonStandardTy,
        ),
        scriptClassTest(
            # Almost nulldata, but add an additional opcode after the data
            # to make it nonstandard.
            name="almost nulldata",
            script="RETURN 4 TRUE",
            scriptClass=txscript.NonStandardTy,
        ),
        # The next few are almost multisig (it is the more complex script type)
        # but with various changes to make it fail.
        scriptClassTest(
            # Multisig but invalid nsigs.
            name="strange 1",
            script="DUP DATA_33 0x0232abdc893e7f0631364d7fd01cb33d24da45"
            + "329a00357b3a7886211ab414d55a 1 CHECKMULTISIG",
            scriptClass=txscript.NonStandardTy,
        ),
        scriptClassTest(
            # Multisig but invalid pubkey.
            name="strange 2",
            script="1 1 1 CHECKMULTISIG",
            scriptClass=txscript.NonStandardTy,
        ),
        scriptClassTest(
            # Multisig but no matching npubkeys opcode.
            name="strange 3",
            script="1 DATA_33 0x0232abdc893e7f0631364d7fd01cb33d24da4532"
            + "9a00357b3a7886211ab414d55a DATA_33 0x0232abdc893e7f0"
            + "631364d7fd01cb33d24da45329a00357b3a7886211ab414d55a "
            + "CHECKMULTISIG",
            scriptClass=txscript.NonStandardTy,
        ),
        scriptClassTest(
            # Multisig but with multisigverify.
            name="strange 4",
            script="1 DATA_33 0x0232abdc893e7f0631364d7fd01cb33d24da4532"
            + "9a00357b3a7886211ab414d55a 1 CHECKMULTISIGVERIFY",
            scriptClass=txscript.NonStandardTy,
        ),
        scriptClassTest(
            # Multisig but wrong length.
            name="strange 5",
            script="1 CHECKMULTISIG",
            scriptClass=txscript.NonStandardTy,
        ),
        scriptClassTest(
            name="doesn't parse",
            script="DATA_5 0x01020304",
            scriptClass=txscript.NonStandardTy,
        ),
        scriptClassTest(
            name="multisig script with wrong number of pubkeys",
            script="2 "
            + "DATA_33 "
            + "0x027adf5df7c965a2d46203c781bd4dd8"
            + "21f11844136f6673af7cc5a4a05cd29380 "
            + "DATA_33 "
            + "0x02c08f3de8ee2de9be7bd770f4c10eb0"
            + "d6ff1dd81ee96eedd3a9d4aeaf86695e80 "
            + "3 CHECKMULTISIG",
            scriptClass=txscript.NonStandardTy,
        ),
    ]


class TestTxScript(unittest.TestCase):
    def test_stake_pool_ticketFee(self):
        class test:
            def __init__(self, StakeDiff, Fee, Height, PoolFee, Expected):
                self.StakeDiff = int(StakeDiff)
                self.Fee = int(Fee)
                self.Height = int(Height)
                self.PoolFee = PoolFee
                self.Expected = int(Expected)

        tests = [
            test(10 * 1e8, 0.01 * 1e8, 25000, 1.00, 0.01500463 * 1e8),
            test(20 * 1e8, 0.01 * 1e8, 25000, 1.00, 0.01621221 * 1e8),
            test(5 * 1e8, 0.05 * 1e8, 50000, 2.59, 0.03310616 * 1e8),
            test(15 * 1e8, 0.05 * 1e8, 50000, 2.59, 0.03956376 * 1e8),
        ]
        cache = SubsidyCache(mainnet)
        for i, t in enumerate(tests):
            poolFeeAmt = txscript.stakePoolTicketFee(
                t.StakeDiff, t.Fee, t.Height, t.PoolFee, cache, mainnet
            )
            self.assertEqual(poolFeeAmt, t.Expected, str(i))

    def test_generate_sstx_addr_push(self):
        """
        TestGenerateSStxAddrPush ensures an expected OP_RETURN push is generated.
        """

        class test:
            def __init__(self, addrStr, net, amount, limits, expected):
                self.addrStr = addrStr
                self.net = net
                self.amount = amount
                self.limits = limits
                self.expected = expected

        tests = []
        tests.append(
            test(
                "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx",
                mainnet,
                1000,
                10,
                ByteArray(
                    "6a1ef5916158e3e2c4551c1796708db8367207ed13bbe8030000000000800a00"
                ),
            )
        )
        tests.append(
            test(
                "TscB7V5RuR1oXpA364DFEsNDuAs8Rk6BHJE",
                testnet,
                543543,
                256,
                ByteArray(
                    "6a1e7a5c4cca76f2e0b36db4763daacbd6cbb6ee6e7b374b0800000000000001"
                ),
            )
        )
        for t in tests:
            addr = txscript.decodeAddress(t.addrStr, t.net)
            s = txscript.generateSStxAddrPush(addr, t.amount, t.limits)
            self.assertEqual(s, t.expected)

    def test_var_int_serialize(self):
        """
        TestVarIntSerializeSize ensures the serialize size for variable length
        integers works as intended.
        """
        tests = [
            (0, 1),  # Single byte encoded
            (0xFC, 1),  # Max single byte encoded
            (0xFD, 3),  # Min 3-byte encoded
            (0xFFFF, 3),  # Max 3-byte encoded
            (0x10000, 5),  # Min 5-byte encoded
            (0xFFFFFFFF, 5),  # Max 5-byte encoded
            (0x100000000, 9),  # Min 9-byte encoded
            (0xFFFFFFFFFFFFFFFF, 9),  # Max 9-byte encoded
        ]

        for i, (val, size) in enumerate(tests):
            self.assertEqual(
                txscript.varIntSerializeSize(val), size, msg="test at index %d" % i
            )

    def test_calc_signature_hash(self):
        """
        TestCalcSignatureHash does some rudimentary testing of msg hash calculation.
        """
        tx = msgtx.MsgTx.new()
        for i in range(3):
            txIn = msgtx.TxIn(
                msgtx.OutPoint(
                    txHash=crypto.hashH(ByteArray(i, length=1).bytes()), idx=i, tree=0,
                ),
                0,
            )
            txIn.sequence = 0xFFFFFFFF

            tx.addTxIn(txIn)
        for i in range(2):
            txOut = msgtx.TxOut()
            txOut.pkScript = ByteArray("51", length=1)
            txOut.value = 0x0000FF00FF00FF00
            tx.addTxOut(txOut)

        want = ByteArray(
            "4ce2cd042d64e35b36fdbd16aff0d38a5abebff0e5e8f6b6b31fcd4ac6957905"
        )
        script = ByteArray("51", length=1)

        msg1 = txscript.calcSignatureHash(script, txscript.SigHashAll, tx, 0, None)

        prefixHash = tx.hash()
        msg2 = txscript.calcSignatureHash(
            script, txscript.SigHashAll, tx, 0, prefixHash
        )

        self.assertEqual(msg1, want)

        self.assertEqual(msg2, want)

        self.assertEqual(msg1, msg2)

        # Move the index and make sure that we get a whole new hash, despite
        # using the same TxOuts.
        msg3 = txscript.calcSignatureHash(
            script, txscript.SigHashAll, tx, 1, prefixHash
        )

        self.assertNotEqual(msg1, msg3)

    def test_script_tokenizer(self):
        """
        TestScriptTokenizer ensures a wide variety of behavior provided by the script
        tokenizer performs as expected.
        """

        # Add both positive and negative tests for OP_DATA_1 through OP_DATA_75.
        tests = []
        for op in range(opcode.OP_DATA_1, opcode.OP_DATA_75):
            data = ByteArray([1] * op)
            tests.append(
                (
                    "OP_DATA_%d" % op,
                    ByteArray(op, length=1) + data,
                    ((op, data, 1 + op),),
                    1 + op,
                    None,
                )
            )

            # Create test that provides one less byte than the data push requires.
            tests.append(
                ("short OP_DATA_%d" % op, ByteArray(op) + data[1:], None, 0, Exception,)
            )

        # Add both positive and negative tests for OP_PUSHDATA{1,2,4}.
        data = ByteArray([1] * 76)
        tests.extend(
            [
                (
                    "OP_PUSHDATA1",
                    ByteArray(opcode.OP_PUSHDATA1)
                    + ByteArray(0x4C)
                    + ByteArray([0x01] * 76),
                    ((opcode.OP_PUSHDATA1, data, 2 + len(data)),),
                    2 + len(data),
                    None,
                ),
                (
                    "OP_PUSHDATA1 no data length",
                    ByteArray(opcode.OP_PUSHDATA1),
                    None,
                    0,
                    Exception,
                ),
                (
                    "OP_PUSHDATA1 short data by 1 byte",
                    ByteArray(opcode.OP_PUSHDATA1)
                    + ByteArray(0x4C)
                    + ByteArray([0x01] * 75),
                    None,
                    0,
                    Exception,
                ),
                (
                    "OP_PUSHDATA2",
                    ByteArray(opcode.OP_PUSHDATA2)
                    + ByteArray(0x4C00)
                    + ByteArray([0x01] * 76),
                    ((opcode.OP_PUSHDATA2, data, 3 + len(data)),),
                    3 + len(data),
                    None,
                ),
                (
                    "OP_PUSHDATA2 no data length",
                    ByteArray(opcode.OP_PUSHDATA2),
                    None,
                    0,
                    Exception,
                ),
                (
                    "OP_PUSHDATA2 short data by 1 byte",
                    ByteArray(opcode.OP_PUSHDATA2)
                    + ByteArray(0x4C00)
                    + ByteArray([0x01] * 75),
                    None,
                    0,
                    Exception,
                ),
                (
                    "OP_PUSHDATA4",
                    ByteArray(opcode.OP_PUSHDATA4)
                    + ByteArray(0x4C000000)
                    + ByteArray([0x01] * 76),
                    ((opcode.OP_PUSHDATA4, data, 5 + len(data)),),
                    5 + len(data),
                    None,
                ),
                (
                    "OP_PUSHDATA4 no data length",
                    ByteArray(opcode.OP_PUSHDATA4),
                    None,
                    0,
                    Exception,
                ),
                (
                    "OP_PUSHDATA4 short data by 1 byte",
                    ByteArray(opcode.OP_PUSHDATA4)
                    + ByteArray(0x4C000000)
                    + ByteArray([0x01] * 75),
                    None,
                    0,
                    Exception,
                ),
            ]
        )

        # Add tests for OP_0, and OP_1 through OP_16 (small integers/true/false).
        opcodes = ByteArray(opcode.OP_0)
        nilBytes = ByteArray("")
        for op in range(opcode.OP_1, opcode.OP_16):
            opcodes += op
        for op in opcodes:
            tests.append(("OP_%d" % op, ByteArray(op), ((op, nilBytes, 1),), 1, None,))

        # Add various positive and negative tests for  multi-opcode scripts.
        tests.extend(
            [
                (
                    "pay-to-pubkey-hash",
                    ByteArray(opcode.OP_DUP)
                    + ByteArray(opcode.OP_HASH160)
                    + ByteArray(opcode.OP_DATA_20)
                    + ByteArray([0x01] * 20)
                    + ByteArray(opcode.OP_EQUAL)
                    + ByteArray(opcode.OP_CHECKSIG),
                    (
                        (opcode.OP_DUP, nilBytes, 1),
                        (opcode.OP_HASH160, nilBytes, 2),
                        (opcode.OP_DATA_20, ByteArray([0x01] * 20), 23),
                        (opcode.OP_EQUAL, nilBytes, 24),
                        (opcode.OP_CHECKSIG, nilBytes, 25),
                    ),
                    25,
                    None,
                ),
                (
                    "almost pay-to-pubkey-hash (short data)",
                    ByteArray(opcode.OP_DUP)
                    + ByteArray(opcode.OP_HASH160)
                    + ByteArray(opcode.OP_DATA_20)
                    + ByteArray([0x01] * 17)
                    + ByteArray(opcode.OP_EQUAL)
                    + ByteArray(opcode.OP_CHECKSIG),
                    ((opcode.OP_DUP, nilBytes, 1), (opcode.OP_HASH160, nilBytes, 2),),
                    2,
                    Exception,
                ),
                (
                    "almost pay-to-pubkey-hash (overlapped data)",
                    ByteArray(opcode.OP_DUP)
                    + ByteArray(opcode.OP_HASH160)
                    + ByteArray(opcode.OP_DATA_20)
                    + ByteArray([0x01] * 19)
                    + ByteArray(opcode.OP_EQUAL)
                    + ByteArray(opcode.OP_CHECKSIG),
                    (
                        (opcode.OP_DUP, nilBytes, 1),
                        (opcode.OP_HASH160, nilBytes, 2),
                        (
                            opcode.OP_DATA_20,
                            ByteArray([0x01] * 19) + ByteArray(opcode.OP_EQUAL),
                            23,
                        ),
                        (opcode.OP_CHECKSIG, nilBytes, 24),
                    ),
                    24,
                    None,
                ),
                (
                    "pay-to-script-hash",
                    ByteArray(opcode.OP_HASH160)
                    + ByteArray(opcode.OP_DATA_20)
                    + ByteArray([0x01] * 20)
                    + ByteArray(opcode.OP_EQUAL),
                    (
                        (opcode.OP_HASH160, nilBytes, 1),
                        (opcode.OP_DATA_20, ByteArray([0x01] * 20), 22),
                        (opcode.OP_EQUAL, nilBytes, 23),
                    ),
                    23,
                    None,
                ),
                (
                    "almost pay-to-script-hash (short data)",
                    ByteArray(opcode.OP_HASH160)
                    + ByteArray(opcode.OP_DATA_20)
                    + ByteArray([0x01] * 18)
                    + ByteArray(opcode.OP_EQUAL),
                    ((opcode.OP_HASH160, nilBytes, 1),),
                    1,
                    Exception,
                ),
                (
                    "almost pay-to-script-hash (overlapped data)",
                    ByteArray(opcode.OP_HASH160)
                    + ByteArray(opcode.OP_DATA_20)
                    + ByteArray([0x01] * 19)
                    + ByteArray(opcode.OP_EQUAL),
                    (
                        (opcode.OP_HASH160, nilBytes, 1),
                        (
                            opcode.OP_DATA_20,
                            ByteArray([0x01] * 19) + ByteArray(opcode.OP_EQUAL),
                            22,
                        ),
                    ),
                    22,
                    None,
                ),
            ]
        )

        scriptVersion = 0
        for test_name, test_script, test_expected, test_finalIdx, test_err in tests:
            tokenizer = txscript.ScriptTokenizer(scriptVersion, test_script)
            opcodeNum = 0
            while tokenizer.next():
                # Ensure Next never returns true when there is an error set.
                self.assertIs(
                    tokenizer.err,
                    None,
                    msg="%s: Next returned true when tokenizer has err: %r"
                    % (test_name, tokenizer.err),
                )

                # Ensure the test data expects a token to be parsed.
                op = tokenizer.opcode()
                data = tokenizer.data()
                self.assertFalse(
                    opcodeNum >= len(test_expected),
                    msg="%s: unexpected token '%r' (data: '%s')"
                    % (test_name, op, data),
                )
                expected_op, expected_data, expected_index = test_expected[opcodeNum]

                # Ensure the opcode and data are the expected values.
                self.assertEqual(
                    op,
                    expected_op,
                    msg="%s: unexpected opcode -- got %d, want %d"
                    % (test_name, op, expected_op),
                )
                self.assertEqual(
                    data,
                    expected_data,
                    msg="%s: unexpected data -- got %s, want %s"
                    % (test_name, data, expected_data),
                )

                tokenizerIdx = tokenizer.offset
                self.assertEqual(
                    tokenizerIdx,
                    expected_index,
                    msg="%s: unexpected byte index -- got %d, want %d"
                    % (test_name, tokenizerIdx, expected_index),
                )

                opcodeNum += 1

            # Ensure the tokenizer claims it is done.  This should be the case
            # regardless of whether or not there was a parse error.
            self.assertTrue(
                tokenizer.done(), msg="%s: tokenizer claims it is not done" % test_name
            )

            # Ensure the error is as expected.
            if test_err is None:
                self.assertIs(
                    tokenizer.err,
                    None,
                    msg="%s: unexpected tokenizer err -- got %r, want None"
                    % (test_name, tokenizer.err),
                )
            else:
                self.assertTrue(
                    isinstance(tokenizer.err, test_err),
                    msg="%s: unexpected tokenizer err -- got %r, want %r"
                    % (test_name, tokenizer.err, test_err),
                )

            # Ensure the final index is the expected value.
            tokenizerIdx = tokenizer.offset
            self.assertEqual(
                tokenizerIdx,
                test_finalIdx,
                msg="%s: unexpected final byte index -- got %d, want %d"
                % (test_name, tokenizerIdx, test_finalIdx),
            )

    def test_signature(self):
        class test:
            def __init__(self, name, sig, der, isValid):
                self.name = name
                self.sig = sig
                self.der = der
                self.isValid = isValid

        # fmt: off
        tests = [
            # signatures from bitcoin blockchain tx
            # 0437cd7f8525ceed2324359c2d0ba26006d92d85
            test(
                "valid signature.",
                [0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                True,
            ),
            test(
                "empty.",
                [],
                "",
                False,
            ),
            test(
                "bad magic.",
                [0x31, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "bad 1st int marker magic.",
                [0x30, 0x44, 0x03, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "bad 2nd int marker.",
                [0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x03, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "short len",
                [0x30, 0x43, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "long len",
                [0x30, 0x45, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "long X",
                [0x30, 0x44, 0x02, 0x42, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "long Y",
                [0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x21, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "short Y",
                [0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x19, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "trailing crap.",
                [0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09, 0x01],
                True,
                # This test is now passing (used to be failing) because there
                # are signatures in the blockchain that have trailing zero
                # bytes before the hashtype. So ParseSignature was fixed to
                # permit buffers with trailing nonsense after the actual
                # signature.
                True,
            ),
            test(
                "X == N ",
                [0x30, 0x44, 0x02, 0x20, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
                    0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "X == N ",
                [0x30, 0x44, 0x02, 0x20, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
                    0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41,
                    0x42, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                False,
                False,
            ),
            test(
                "Y == N",
                [0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41],
                True,
                False,
            ),
            test(
                "Y > N",
                [0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x42],
                False,
                False,
            ),
            test(
                "0 len X.",
                [0x30, 0x24, 0x02, 0x00, 0x02, 0x20, 0x18, 0x15,
                    0x22, 0xec, 0x8e, 0xca, 0x07, 0xde, 0x48, 0x60, 0xa4,
                    0xac, 0xdd, 0x12, 0x90, 0x9d, 0x83, 0x1c, 0xc5, 0x6c,
                    0xbb, 0xac, 0x46, 0x22, 0x08, 0x22, 0x21, 0xa8, 0x76,
                    0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "0 len Y.",
                [0x30, 0x24, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x00],
                True,
                False,
            ),
            test(
                "extra R padding.",
                [0x30, 0x45, 0x02, 0x21, 0x00, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            test(
                "extra S padding.",
                [0x30, 0x45, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x21, 0x00, 0x18, 0x15, 0x22, 0xec, 0x8e, 0xca,
                    0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90,
                    0x9d, 0x83, 0x1c, 0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22,
                    0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09],
                True,
                False,
            ),
            # Standard checks (in BER format, without checking for 'canonical' DER
            # signatures) don't test for negative numbers here because there isn't
            # a way that is the same between openssl and go that will mark a number
            # as negative. The Go ASN.1 parser marks numbers as negative when
            # openssl does not (it doesn't handle negative numbers that I can tell
            # at all. When not parsing DER signatures, which is done by by bitcoind
            # when accepting transactions into its mempool, we otherwise only check
            # for the coordinates being zero.
            test(
                "X == 0",
                [0x30, 0x25, 0x02, 0x01, 0x00, 0x02, 0x20, 0x18,
                    0x15, 0x22, 0xec, 0x8e, 0xca, 0x07, 0xde, 0x48, 0x60,
                    0xa4, 0xac, 0xdd, 0x12, 0x90, 0x9d, 0x83, 0x1c, 0xc5,
                    0x6c, 0xbb, 0xac, 0x46, 0x22, 0x08, 0x22, 0x21, 0xa8,
                    0x76, 0x8d, 0x1d, 0x09],
                False,
                False,
            ),
            test(
                "Y == 0.",
                [0x30, 0x25, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
                    0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
                    0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
                    0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
                    0x41, 0x02, 0x01, 0x00],
                False,
                False,
            ),
        ]
        # fmt: on
        for test in tests:
            try:
                txscript.Signature.parse(ByteArray(test.sig), test.der)
            except Exception:
                self.assertFalse(test.isValid)

    def test_sign_tx(self):
        """
        Based on dcrd TestSignTxOutput.
        """
        # make key
        # make script based on key.
        # sign with magic pixie dust.
        hashTypes = (
            txscript.SigHashAll,
            # SigHashNone,
            # SigHashSingle,
            # SigHashAll | SigHashAnyOneCanPay,
            # SigHashNone | SigHashAnyOneCanPay,
            # SigHashSingle | SigHashAnyOneCanPay,
        )
        signatureSuites = (
            crypto.STEcdsaSecp256k1,
            # crypto.STEd25519,
            # crypto.STSchnorrSecp256k1,
        )

        testValueIn = 12345
        tx = msgtx.MsgTx(
            serType=wire.TxSerializeFull,
            version=1,
            txIn=[
                msgtx.TxIn(
                    previousOutPoint=msgtx.OutPoint(
                        txHash=ByteArray(b""), idx=0, tree=0,
                    ),
                    sequence=4294967295,
                    valueIn=testValueIn,
                    blockHeight=78901,
                    blockIndex=23456,
                ),
                msgtx.TxIn(
                    previousOutPoint=msgtx.OutPoint(
                        txHash=ByteArray(b""), idx=1, tree=0,
                    ),
                    sequence=4294967295,
                    valueIn=testValueIn,
                    blockHeight=78901,
                    blockIndex=23456,
                ),
                msgtx.TxIn(
                    previousOutPoint=msgtx.OutPoint(
                        txHash=ByteArray(b""), idx=2, tree=0,
                    ),
                    sequence=4294967295,
                    valueIn=testValueIn,
                    blockHeight=78901,
                    blockIndex=23456,
                ),
            ],
            txOut=[
                msgtx.TxOut(version=wire.DefaultPkScriptVersion, value=1,),
                msgtx.TxOut(version=wire.DefaultPkScriptVersion, value=2,),
                msgtx.TxOut(version=wire.DefaultPkScriptVersion, value=3,),
            ],
            lockTime=0,
            expiry=0,
            cachedHash=None,
        )

        # Since the script engine is not implmented, hard code the keys and
        # check that the script signature is the same as produced by dcrd.

        # For compressed keys
        tests = (
            (
                "b78a743c0c6557f24a51192b82925942ebade0be86efd7dad58b9fa358d3857c",
                "47304402203220ddaee5e825376d3ae5a0e20c463a45808e066abc3c8c33a133"
                "446a4c9eb002200f2b0b534d5294d9ce5974975ab5af11696535c4c76cadaed1"
                "fa327d6d210e19012102e11d2c0e415343435294079ac0774a21c8e6b1e6fd9b"
                "671cb08af43a397f3df1",
            ),
            (
                "a00616c21b117ba621d4c72faf30d30cd665416bdc3c24e549de2348ac68cfb8",
                "473044022020eb42f1965c31987a4982bd8f654d86c1451418dd3ccc0a342faa"
                "98a384186b022021cd0dcd767e607df159dd25674469e1d172e66631593bf960"
                "23519d5c07c43101210224397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3"
                "eec05d913e2e8e04396b",
            ),
            (
                "8902ea1f64c6fb7aa40dfbe798f5dc53b466a3fc01534e867581936a8ecbff5b",
                "483045022100d71babc95de02df7be1e7b14c0f68fb5dcab500c8ef7cf8172b2"
                "ea8ad627533302202968ddc3b2f9ff07d3a736b04e74fa39663f028035b6d175"
                "de6a4ef90838b797012103255f71eab9eb2a7e3f822569484448acbe2880d61b"
                "4db61020f73fd54cbe370d",
            ),
        )

        # For uncompressed keys
        # tests = (
        #     (
        #         "b78a743c0c6557f24a51192b82925942ebade0be86efd7dad58b9fa358d3857c",
        #         "483045022100e1bab52fe0b460c71e4a4226ada35ebbbff9959835fa26c70e25"
        #         "71ef2634a05b02200683f9bf8233ba89c5f9658041cc8edc56feef74cad238f0"
        #         "60c3b04e0c4f1cb1014104e11d2c0e415343435294079ac0774a21c8e6b1e6fd"
        #         "9b671cb08af43a397f3df1c4d3fa86c79cfe4f9d13f1c31fd75de316cdfe913b"
        #         "03c07252b1f02f7ee15c9c"
        #     ),
        #     (
        #         "a00616c21b117ba621d4c72faf30d30cd665416bdc3c24e549de2348ac68cfb8",
        #         "473044022029cf920fe059ca4d7e5d74060ed234ebcc7bca520dfed7238dc1e3"
        #         "2a48d182a9022043141a443740815baf0caffc19ff7b948d41424832b4a9c627"
        #         "3be5beb15ed7ce01410424397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3"
        #         "eec05d913e2e8e04396b422f7f8591e7a4030eddb635e753523bce3c6025fc4e"
        #         "97987adb385b08984e94"
        #     ),
        #     (
        #         "8902ea1f64c6fb7aa40dfbe798f5dc53b466a3fc01534e867581936a8ecbff5b",
        #         "473044022015f417f05573c3201f96f5ae706c0789539e638a4a57915dc077b8"
        #         "134c83f1ff022001afa12cebd5daa04d7a9d261d78d0fb910294d78c269fe0b2"
        #         "aabc2423282fe5014104255f71eab9eb2a7e3f822569484448acbe2880d61b4d"
        #         "b61020f73fd54cbe370d031fee342d455077982fe105e82added63ad667f0b61"
        #         "6f3c2c17e1cc9205f3d1"
        #     ),
        # )

        # Pay to Pubkey Hash (compressed)
        testingParams = mainnet
        for hashType in hashTypes:
            for suite in signatureSuites:
                for idx in range(len(tx.txIn)):
                    # var keyDB, pkBytes []byte
                    # var key chainec.PrivateKey
                    # var pk chainec.PublicKey
                    kStr, sigStr = tests[idx]

                    if suite == crypto.STEcdsaSecp256k1:
                        # k = Curve.generateKey(rand.Reader)
                        k = ByteArray(kStr)
                        privKey = crypto.privKeyFromBytes(k)
                        pkBytes = privKey.pub.serializeCompressed()
                    else:
                        raise Exception(
                            "test for signature suite %d not implemented" % suite
                        )

                    address = crypto.newAddressPubKeyHash(
                        crypto.hash160(pkBytes.bytes()), testingParams, suite
                    )

                    pkScript = txscript.makePayToAddrScript(
                        address.string(), testingParams
                    )

                    class keysource:
                        @staticmethod
                        def priv(addr):
                            return privKey

                    sigScript = txscript.signTxOutput(
                        testingParams,
                        tx,
                        idx,
                        pkScript,
                        hashType,
                        keysource,
                        None,
                        suite,
                    )

                    self.assertEqual(
                        sigScript,
                        ByteArray(sigStr),
                        msg="%d:%d:%d" % (hashType, idx, suite),
                    )

        # Pay to Pubkey Hash for a ticket (SStx) (compressed)
        # For compressed keys
        tests = (
            (
                "b78a743c0c6557f24a51192b82925942ebade0be86efd7dad58b9fa358d3857c",
                "4730440220411b0a068d5b1c5fd6ec98a0e3f17ce632a863a9d57876c0bde2647a8dcd26c602204f05f109f0f185cc79a43168411075eb58fd350cc135f4872b0b8c81015e21c3012102e11d2c0e415343435294079ac0774a21c8e6b1e6fd9b671cb08af43a397f3df1",
            ),
            (
                "a00616c21b117ba621d4c72faf30d30cd665416bdc3c24e549de2348ac68cfb8",
                "473044022050a359daf7db3db11e95ceb8494173f8ca168b32ccc6cc57dcad5f78564678af02200c09e2c7c72736ef9835f05eb0c6eb72fdd2e1e98cdaf7af7f2d9523ed5f410501210224397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3eec05d913e2e8e04396b",
            ),
            (
                "8902ea1f64c6fb7aa40dfbe798f5dc53b466a3fc01534e867581936a8ecbff5b",
                "4730440220257fe3c52ce408561aec4446c30bca6d6fad98ba554917c4e7714a89badbfdbf02201aa569c5e28d728dd20ce32656915729ebc6679527bfe2401ea3723791e04538012103255f71eab9eb2a7e3f822569484448acbe2880d61b4db61020f73fd54cbe370d",
            ),
        )

        testingParams = mainnet
        for hashType in hashTypes:
            for suite in signatureSuites:
                for idx in range(len(tx.txIn)):
                    # var keyDB, pkBytes []byte
                    # var key chainec.PrivateKey
                    # var pk chainec.PublicKey
                    kStr, sigStr = tests[idx]

                    if suite == crypto.STEcdsaSecp256k1:
                        # k = Curve.generateKey(rand.Reader)
                        k = ByteArray(kStr)
                        privKey = crypto.privKeyFromBytes(k)
                        pkBytes = privKey.pub.serializeCompressed()
                    else:
                        raise Exception(
                            "test for signature suite %d not implemented" % suite
                        )

                    address = crypto.newAddressPubKeyHash(
                        crypto.hash160(pkBytes.bytes()), testingParams, suite
                    )

                    pkScript = txscript.payToSStx(address)

                    class keysource:
                        @staticmethod
                        def priv(addr):
                            return privKey

                    sigScript = txscript.signTxOutput(
                        testingParams,
                        tx,
                        idx,
                        pkScript,
                        hashType,
                        keysource,
                        None,
                        suite,
                    )

                    self.assertEqual(
                        sigScript,
                        ByteArray(sigStr),
                        msg="%d:%d:%d" % (hashType, idx, suite),
                    )

        # Pay to Pubkey Hash for a ticket revocation (SSRtx) (compressed)
        # For compressed keys
        tests = (
            (
                "b78a743c0c6557f24a51192b82925942ebade0be86efd7dad58b9fa358d3857c",
                "483045022100ad46b5bd365af6964562bfac90abad9d9cf30fdc53ae4011103c646df04a7d5f022076209ea5626cb9a3f16add11c361f6f66c7436eec8efe1688e43ac9f71a86b88012102e11d2c0e415343435294079ac0774a21c8e6b1e6fd9b671cb08af43a397f3df1",
            ),
            (
                "a00616c21b117ba621d4c72faf30d30cd665416bdc3c24e549de2348ac68cfb8",
                "483045022100eeacc7f3fcba009f6ab319b2221e64d52d94d5009cfd037ef03c86dc1bcb2c990220212000f05d1a904d3d995b18b8b94bd0e84dc35aa308df5149094678f6cd40e501210224397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3eec05d913e2e8e04396b",
            ),
            (
                "8902ea1f64c6fb7aa40dfbe798f5dc53b466a3fc01534e867581936a8ecbff5b",
                "47304402200fa66dd2be65cd8c0e89bc299b99cadac36805af627432cbdc968c53b4c4f41b02200b117b145dfdb6ba7846b9b02c63d85d11bfc2188f58f083da6bb88220a9e517012103255f71eab9eb2a7e3f822569484448acbe2880d61b4db61020f73fd54cbe370d",
            ),
        )

        testingParams = mainnet
        for hashType in hashTypes:
            for suite in signatureSuites:
                for idx in range(len(tx.txIn)):
                    # var keyDB, pkBytes []byte
                    # var key chainec.PrivateKey
                    # var pk chainec.PublicKey
                    kStr, sigStr = tests[idx]

                    if suite == crypto.STEcdsaSecp256k1:
                        # k = Curve.generateKey(rand.Reader)
                        k = ByteArray(kStr)
                        privKey = crypto.privKeyFromBytes(k)
                        pkBytes = privKey.pub.serializeCompressed()
                    else:
                        raise Exception(
                            "test for signature suite %d not implemented" % suite
                        )

                    address = crypto.newAddressPubKeyHash(
                        crypto.hash160(pkBytes.bytes()), testingParams, suite
                    )

                    pkScript = txscript.payToSSRtxPKHDirect(
                        txscript.decodeAddress(
                            address.string(), testingParams
                        ).scriptAddress()
                    )

                    class keysource:
                        @staticmethod
                        def priv(addr):
                            return privKey

                    sigScript = txscript.signTxOutput(
                        testingParams,
                        tx,
                        idx,
                        pkScript,
                        hashType,
                        keysource,
                        None,
                        suite,
                    )

                    self.assertEqual(
                        sigScript,
                        ByteArray(sigStr),
                        msg="%d:%d:%d" % (hashType, idx, suite),
                    )

        # Basic Multisig (compressed)
        # For compressed keys
        tests = (
            (
                "b78a743c0c6557f24a51192b82925942ebade0be86efd7dad58b9fa358d3857c",
                "483045022100f12b12474e64b807eaeda6ac05b26d4b6bee2519385a84815f4ec2ccdf0aa45b022055c590d36a172c4735c8886572723037dc65329e70b8e5e012a9ec24993c284201483045022100ae2fec7236910b0bbc5eab37b7d987d61f22139f6381f2cc9781373e4f470c37022037d8b1658c2a83c40cc1b97036239eb0f4b313f3d2bf4558de33412e834c45d50147522102e11d2c0e415343435294079ac0774a21c8e6b1e6fd9b671cb08af43a397f3df1210224397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3eec05d913e2e8e04396b52ae",
            ),
            (
                "a00616c21b117ba621d4c72faf30d30cd665416bdc3c24e549de2348ac68cfb8",
                "473044022047b34afd287cacbc4ba0d95d985b23a55069c0bd81d61eb32435348bef2dc6c602201e4c7c0c437d4d53172cac355eadd70c8b87d3936c7a0a0179201b9b9327852d01483045022100df1975379ac38dcc5caddb1f55974b5b08a22b4fdb6e88be9ba12da0c0ecfbed022042bc3420adde7410f463caa998a460d58b214bf082e004b5067a4c0f061e0769014752210224397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3eec05d913e2e8e04396b2103255f71eab9eb2a7e3f822569484448acbe2880d61b4db61020f73fd54cbe370d52ae",
            ),
            (
                "8902ea1f64c6fb7aa40dfbe798f5dc53b466a3fc01534e867581936a8ecbff5b",
                "473044022002d1251cb8a2f1a20225948f99e6c71a188915c3ca0dc433ca9c35c050ee1dd602206880d041a9a9f9888ab751a371768bffd89251edf354eccdac73fe1376095ba20147304402204ddebf367aea5750123c2b4807815487d07239c776b6cc70a99c46a8b3261f4c022044549b4aeda7eb08692fa500b5518655be61fd5299c07adf0caddf41ab391dd00147522103255f71eab9eb2a7e3f822569484448acbe2880d61b4db61020f73fd54cbe370d2102e11d2c0e415343435294079ac0774a21c8e6b1e6fd9b671cb08af43a397f3df152ae",
            ),
        )

        testingParams = mainnet
        for hashType in hashTypes:
            # TODO enable this test after script-hash script signing is implemented
            break
            for suite in signatureSuites:
                for idx in range(len(tx.txIn)):
                    # var keyDB, pkBytes []byte
                    # var key chainec.PrivateKey
                    # var pk chainec.PublicKey
                    kStr, sigStr = tests[idx]
                    kStr2, _ = tests[(idx + 1) % 3]

                    if suite == crypto.STEcdsaSecp256k1:
                        # k = Curve.generateKey(rand.Reader)
                        k = ByteArray(kStr)
                        k2 = ByteArray(kStr2)
                        privKey = crypto.privKeyFromBytes(k)
                        privKey2 = crypto.privKeyFromBytes(k2)
                        pkBytes = privKey.pub.serializeCompressed()
                        pkBytes2 = privKey2.pub.serializeCompressed()
                    else:
                        raise Exception(
                            "test for signature suite %d not implemented" % suite
                        )

                    address = crypto.AddressSecpPubKey(pkBytes.bytes(), testingParams)

                    address2 = crypto.AddressSecpPubKey(pkBytes2.bytes(), testingParams)

                    pkScript = txscript.multiSigScript([address, address2], 2)

                    scriptAddr = crypto.newAddressScriptHash(pkScript, testingParams)

                    scriptPkScript = txscript.payToAddrScript(scriptAddr)

                    keys = iter([privKey, privKey2])

                    class keysource:
                        @staticmethod
                        def priv(addr):
                            return next(keys)

                    sigScript = txscript.signTxOutput(
                        testingParams,
                        tx,
                        idx,
                        scriptPkScript,
                        hashType,
                        keysource,
                        None,
                        suite,
                    )
                    print(sigScript.hex())

                    self.assertEqual(
                        sigScript,
                        ByteArray(sigStr),
                        msg="%d:%d:%d" % (hashType, idx, suite),
                    )

    def test_sign_stake_p2pkh_outputs(self):
        txIn = msgtx.TxIn(
            previousOutPoint=msgtx.OutPoint(
                txHash=ByteArray(rando.generateSeed(32)), idx=0, tree=0,
            ),
            sequence=4294967295,
            valueIn=1,
            blockHeight=78901,
            blockIndex=23456,
        )
        tx = msgtx.MsgTx(
            serType=wire.TxSerializeFull,
            version=1,
            txIn=[txIn],
            txOut=[msgtx.TxOut(version=wire.DefaultPkScriptVersion, value=1)],
            lockTime=0,
            expiry=0,
            cachedHash=None,
        )

        privKey = Curve.generateKey()
        pkHash = crypto.hash160(privKey.pub.serializeCompressed().b)
        addr = crypto.AddressPubKeyHash(mainnet.PubKeyHashAddrID, pkHash)

        class keysource:
            @staticmethod
            def priv(addr):
                return privKey

        for opCode in (opcode.OP_SSGEN, opcode.OP_SSRTX, opcode.OP_SSTX):
            pkScript = txscript.payToStakePKHScript(addr, opcode.OP_SSTX)
            # Just looking to raise an exception for now.
            txscript.signTxOutput(
                mainnet,
                tx,
                0,
                pkScript,
                txscript.SigHashAll,
                keysource,
                None,
                crypto.STEcdsaSecp256k1,
            )

    def test_addresses(self):
        class test:
            def __init__(
                self,
                name="",
                addr="",
                saddr="",
                encoded="",
                valid=False,
                scriptAddress=None,
                f=None,
                net=None,
            ):
                self.name = name
                self.addr = addr
                self.saddr = saddr
                self.encoded = encoded
                self.valid = valid
                self.scriptAddress = scriptAddress
                self.f = f
                self.net = net

        addrPKH = crypto.newAddressPubKeyHash
        addrSH = crypto.newAddressScriptHash
        addrSHH = crypto.newAddressScriptHashFromHash
        addrPK = crypto.AddressSecpPubKey

        tests = []
        # Positive P2PKH tests.
        tests.append(
            test(
                name="mainnet p2pkh",
                addr="DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
                encoded="DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
                valid=True,
                scriptAddress=ByteArray("2789d58cfa0957d206f025c2af056fc8a77cebb0"),
                f=lambda: addrPKH(
                    ByteArray("2789d58cfa0957d206f025c2af056fc8a77cebb0"),
                    mainnet,
                    crypto.STEcdsaSecp256k1,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                name="mainnet p2pkh 2",
                addr="DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9",
                encoded="DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9",
                valid=True,
                scriptAddress=ByteArray("229ebac30efd6a69eec9c1a48e048b7c975c25f2"),
                f=lambda: addrPKH(
                    ByteArray("229ebac30efd6a69eec9c1a48e048b7c975c25f2"),
                    mainnet,
                    crypto.STEcdsaSecp256k1,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                name="testnet p2pkh",
                addr="Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h",
                encoded="Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h",
                valid=True,
                scriptAddress=ByteArray("f15da1cb8d1bcb162c6ab446c95757a6e791c916"),
                f=lambda: addrPKH(
                    ByteArray("f15da1cb8d1bcb162c6ab446c95757a6e791c916"),
                    testnet,
                    crypto.STEcdsaSecp256k1,
                ),
                net=testnet,
            )
        )

        # Negative P2PKH tests.
        tests.append(
            test(
                name="p2pkh wrong hash length",
                addr="",
                valid=False,
                f=lambda: addrPKH(
                    ByteArray("000ef030107fd26e0b6bf40512bca2ceb1dd80adaa"),
                    mainnet,
                    crypto.STEcdsaSecp256k1,
                ),
            )
        )
        tests.append(
            test(
                name="p2pkh bad checksum",
                addr="TsmWaPM77WSyA3aiQ2Q1KnwGDVWvEkhip23",
                valid=False,
                net=testnet,
            )
        )

        # Positive P2SH tests.
        tests.append(
            test(
                # Taken from transactions:
                # output: 3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac
                # input:  837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba.
                name="mainnet p2sh",
                addr="DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
                encoded="DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
                valid=True,
                scriptAddress=ByteArray("f0b4e85100aee1a996f22915eb3c3f764d53779a"),
                f=lambda: addrSH(
                    ByteArray(
                        "512103aa43f0a6c15730d886cc1f0342046d2"
                        "0175483d90d7ccb657f90c489111d794c51ae"
                    ),
                    mainnet,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                # Taken from transactions:
                # output: b0539a45de13b3e0403909b8bd1a555b8cbe45fd4e3f3fda76f3a5f52835c29d
                # input: (not yet redeemed at time test was written)
                name="mainnet p2sh 2",
                addr="DcqgK4N4Ccucu2Sq4VDAdu4wH4LASLhzLVp",
                encoded="DcqgK4N4Ccucu2Sq4VDAdu4wH4LASLhzLVp",
                valid=True,
                scriptAddress=ByteArray("c7da5095683436f4435fc4e7163dcafda1a2d007"),
                f=lambda: addrSHH(
                    ByteArray("c7da5095683436f4435fc4e7163dcafda1a2d007"), mainnet,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                # Taken from bitcoind base58_keys_valid.
                name="testnet p2sh",
                addr="TccWLgcquqvwrfBocq5mcK5kBiyw8MvyvCi",
                encoded="TccWLgcquqvwrfBocq5mcK5kBiyw8MvyvCi",
                valid=True,
                scriptAddress=ByteArray("36c1ca10a8a6a4b5d4204ac970853979903aa284"),
                f=lambda: addrSHH(
                    ByteArray("36c1ca10a8a6a4b5d4204ac970853979903aa284"), testnet,
                ),
                net=testnet,
            )
        )

        # Negative P2SH tests.
        tests.append(
            test(
                name="p2sh wrong hash length",
                addr="",
                valid=False,
                f=lambda: addrSHH(
                    ByteArray("00f815b036d9bbbce5e9f2a00abd1bf3dc91e95510"), mainnet,
                ),
                net=mainnet,
            )
        )

        # Positive P2PK tests.
        tests.append(
            test(
                name="mainnet p2pk compressed (0x02)",
                addr="DsT4FDqBKYG1Xr8aGrT1rKP3kiv6TZ5K5th",
                encoded="DsT4FDqBKYG1Xr8aGrT1rKP3kiv6TZ5K5th",
                valid=True,
                scriptAddress=ByteArray(
                    "028f53838b7639563f27c94845549a41e5146bcd52e7fef0ea6da143a02b0fe2ed"
                ),
                f=lambda: addrPK(
                    ByteArray(
                        "028f53838b7639563f27c94845549a41e5146bcd52e7fef0ea6da143a02b0fe2ed"
                    ),
                    mainnet,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                name="mainnet p2pk compressed (0x03)",
                addr="DsfiE2y23CGwKNxSGjbfPGeEW4xw1tamZdc",
                encoded="DsfiE2y23CGwKNxSGjbfPGeEW4xw1tamZdc",
                valid=True,
                scriptAddress=ByteArray(
                    "03e925aafc1edd44e7c7f1ea4fb7d265dc672f204c3d0c81930389c10b81fb75de"
                ),
                f=lambda: addrPK(
                    ByteArray(
                        "03e925aafc1edd44e7c7f1ea4fb7d265dc672f204c3d0c81930389c10b81fb75de"
                    ),
                    mainnet,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                name="mainnet p2pk uncompressed (0x04)",
                addr="DkM3EyZ546GghVSkvzb6J47PvGDyntqiDtFgipQhNj78Xm2mUYRpf",
                encoded="DsfFjaADsV8c5oHWx85ZqfxCZy74K8RFuhK",
                valid=True,
                saddr="0264c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f0",
                scriptAddress=ByteArray(
                    "0464c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f"
                    "0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"
                ),
                f=lambda: addrPK(
                    ByteArray(
                        "0464c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f"
                        "0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"
                    ),
                    mainnet,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                name="testnet p2pk compressed (0x02)",
                addr="Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
                encoded="Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
                valid=True,
                scriptAddress=ByteArray(
                    "026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e"
                ),
                f=lambda: addrPK(
                    ByteArray(
                        "026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e"
                    ),
                    testnet,
                ),
                net=testnet,
            )
        )
        tests.append(
            test(
                name="testnet p2pk compressed (0x03)",
                addr="TsWZ1EzypJfMwBKAEDYKuyHRGctqGAxMje2",
                encoded="TsWZ1EzypJfMwBKAEDYKuyHRGctqGAxMje2",
                valid=True,
                scriptAddress=ByteArray(
                    "030844ee70d8384d5250e9bb3a6a73d4b5bec770e8b31d6a0ae9fb739009d91af5"
                ),
                f=lambda: addrPK(
                    ByteArray(
                        "030844ee70d8384d5250e9bb3a6a73d4b5bec770e8b31d6a0ae9fb739009d91af5"
                    ),
                    testnet,
                ),
                net=testnet,
            )
        )
        tests.append(
            test(
                name="testnet p2pk uncompressed (0x04)",
                addr="TkKmMiY5iDh4U3KkSopYgkU1AzhAcQZiSoVhYhFymZHGMi9LM9Fdt",
                encoded="Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
                valid=True,
                saddr="026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e",
                scriptAddress=ByteArray(
                    "046a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06"
                    "ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"
                ),
                f=lambda: addrPK(
                    ByteArray(
                        "046a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06"
                        "ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"
                    ),
                    testnet,
                ),
                net=testnet,
            )
        )

        # Negative P2PK tests.
        tests.append(
            test(
                name="mainnet p2pk hybrid (0x06)",
                addr="",
                valid=False,
                f=lambda: addrPK(
                    ByteArray(
                        "0664c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f"
                        "0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"
                    ),
                    mainnet,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                name="mainnet p2pk hybrid (0x07)",
                addr="",
                valid=False,
                f=lambda: addrPK(
                    ByteArray(
                        "07348d8aeb4253ca52456fe5da94ab1263bfee16bb8192497f666389ca964f847"
                        "98375129d7958843b14258b905dc94faed324dd8a9d67ffac8cc0a85be84bac5d"
                    ),
                    mainnet,
                ),
                net=mainnet,
            )
        )
        tests.append(
            test(
                name="testnet p2pk hybrid (0x06)",
                addr="",
                valid=False,
                f=lambda: addrPK(
                    ByteArray(
                        "066a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06"
                        "ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"
                    ),
                    testnet,
                ),
                net=testnet,
            )
        )
        tests.append(
            test(
                name="testnet p2pk hybrid (0x07)",
                addr="",
                valid=False,
                f=lambda: addrPK(
                    ByteArray(
                        "07edd40747de905a9becb14987a1a26c1adbd617c45e1583c142a635bfda9493d"
                        "fa1c6d36735974965fe7b861e7f6fcc087dc7fe47380fa8bde0d9c322d53c0e89"
                    ),
                    testnet,
                ),
                net=testnet,
            )
        )

        for test in tests:
            # Decode addr and compare error against valid.
            err = None
            try:
                decoded = txscript.decodeAddress(test.addr, test.net)
            except Exception as e:
                err = e
            self.assertEqual(err is None, test.valid, "%s error: %s" % (test.name, err))

            if err is None:
                # Ensure the stringer returns the same address as the original.
                self.assertEqual(test.addr, decoded.string(), test.name)

                # Encode again and compare against the original.
                encoded = decoded.address()
                self.assertEqual(test.encoded, encoded)

                # Perform type-specific calculations.
                if isinstance(decoded, crypto.AddressPubKeyHash):
                    d = ByteArray(b58decode(encoded))
                    saddr = d[2 : 2 + crypto.RIPEMD160_SIZE]

                elif isinstance(decoded, crypto.AddressScriptHash):
                    d = ByteArray(b58decode(encoded))
                    saddr = d[2 : 2 + crypto.RIPEMD160_SIZE]

                elif isinstance(decoded, crypto.AddressSecpPubKey):
                    # Ignore the error here since the script
                    # address is checked below.
                    try:
                        saddr = ByteArray(decoded.string())
                    except Exception:
                        saddr = test.saddr

                elif isinstance(decoded, crypto.AddressEdwardsPubKey):
                    # Ignore the error here since the script
                    # address is checked below.
                    # saddr = ByteArray(decoded.String())
                    self.fail("Edwards sigs unsupported")

                elif isinstance(decoded, crypto.AddressSecSchnorrPubKey):
                    # Ignore the error here since the script
                    # address is checked below.
                    # saddr = ByteArray(decoded.String())
                    self.fail("Schnorr sigs unsupported")

                # Check script address, as well as the Hash160 method for P2PKH and
                # P2SH addresses.
                self.assertEqual(saddr, decoded.scriptAddress(), test.name)

                if isinstance(decoded, crypto.AddressPubKeyHash):
                    self.assertEqual(decoded.pkHash, saddr)

                if isinstance(decoded, crypto.AddressScriptHash):
                    self.assertEqual(decoded.hash160(), saddr)

            if not test.valid:
                # If address is invalid, but a creation function exists,
                # verify that it returns a nil addr and non-nil error.
                if test.f is not None:
                    try:
                        test.f()
                        self.fail(
                            "%s: address is invalid but creating new address succeeded"
                            % test.name
                        )
                    except Exception:
                        pass
                continue

            # Valid test, compare address created with f against expected result.
            try:
                addr = test.f()
            except Exception as e:
                self.fail(
                    "%s: address is valid but creating new address failed with error %s",
                    test.name,
                    e,
                )
            self.assertEqual(addr.scriptAddress(), test.scriptAddress, test.name)

    def test_extract_script_addrs(self):
        scriptVersion = 0
        tests = []

        def pkAddr(b):
            addr = crypto.AddressSecpPubKey(b, mainnet)
            # force the format to compressed, as per golang tests.
            addr.pubkeyFormat = crypto.PKFCompressed
            return addr

        class test:
            def __init__(
                self,
                name="",
                script=b"",
                addrs=None,
                reqSigs=-1,
                scriptClass=-1,
                exception=None,
            ):
                self.name = name
                self.script = script
                self.addrs = addrs if addrs else []
                self.reqSigs = reqSigs
                self.scriptClass = scriptClass
                self.exception = exception

        tests.append(
            test(
                name="standard p2pk with compressed pubkey (0x02)",
                script=ByteArray(
                    "2102192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4ac"
                ),
                addrs=[
                    pkAddr(
                        ByteArray(
                            "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"
                        )
                    )
                ],
                reqSigs=1,
                scriptClass=txscript.PubKeyTy,
            )
        )
        tests.append(
            test(
                name="standard p2pk with uncompressed pubkey (0x04)",
                script=ByteArray(
                    "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5"
                    "cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
                ),
                addrs=[
                    pkAddr(
                        ByteArray(
                            "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5"
                            "cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
                        )
                    ),
                ],
                reqSigs=1,
                scriptClass=txscript.PubKeyTy,
            )
        )
        tests.append(
            test(
                name="standard p2pk with compressed pubkey (0x03)",
                script=ByteArray(
                    "2103b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65ac"
                ),
                addrs=[
                    pkAddr(
                        ByteArray(
                            "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"
                        )
                    )
                ],
                reqSigs=1,
                scriptClass=txscript.PubKeyTy,
            )
        )
        tests.append(
            test(
                name="2nd standard p2pk with uncompressed pubkey (0x04)",
                script=ByteArray(
                    "4104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6"
                    "537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac"
                ),
                addrs=[
                    pkAddr(
                        ByteArray(
                            "04b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6"
                            "537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b"
                        )
                    ),
                ],
                reqSigs=1,
                scriptClass=txscript.PubKeyTy,
            )
        )
        tests.append(
            test(
                name="standard p2pkh",
                script=ByteArray("76a914ad06dd6ddee55cbca9a9e3713bd7587509a3056488ac"),
                addrs=[
                    crypto.newAddressPubKeyHash(
                        ByteArray("ad06dd6ddee55cbca9a9e3713bd7587509a30564"),
                        mainnet,
                        crypto.STEcdsaSecp256k1,
                    )
                ],
                reqSigs=1,
                scriptClass=txscript.PubKeyHashTy,
            )
        )
        tests.append(
            test(
                name="standard p2sh",
                script=ByteArray("a91463bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb87"),
                addrs=[
                    crypto.newAddressScriptHashFromHash(
                        ByteArray("63bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb"), mainnet
                    )
                ],
                reqSigs=1,
                scriptClass=txscript.ScriptHashTy,
            )
        )
        # from real tx 60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1, vout 0
        tests.append(
            test(
                name="standard 1 of 2 multisig",
                script=ByteArray(
                    "514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1"
                    "dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec0"
                    "22b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d8"
                    "0e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946"
                    "d8a540911abe3e7854a26f39f58b25c15342af52ae"
                ),
                addrs=[
                    pkAddr(
                        ByteArray(
                            "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb1"
                            "69a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e"
                            "3cf8f065dec022b51d11fcdd0d348ac4"
                        )
                    ),
                    pkAddr(
                        ByteArray(
                            "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a"
                            "34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540"
                            "911abe3e7854a26f39f58b25c15342af"
                        )
                    ),
                ],
                reqSigs=1,
                scriptClass=txscript.MultiSigTy,
            )
        )
        # from real tx d646f82bd5fbdb94a36872ce460f97662b80c3050ad3209bef9d1e398ea277ab, vin 1
        tests.append(
            test(
                name="standard 2 of 3 multisig",
                script=ByteArray(
                    "524104cb9c3c222c5f7a7d3b9bd152f363a0b6d54c9eb312c4d4f9af1e"
                    "8551b6c421a6a4ab0e29105f24de20ff463c1c91fcf3bf662cdde4783d"
                    "4799f787cb7c08869b4104ccc588420deeebea22a7e900cc8b68620d22"
                    "12c374604e3487ca08f1ff3ae12bdc639514d0ec8612a2d3c519f084d9"
                    "a00cbbe3b53d071e9b09e71e610b036aa24104ab47ad1939edcb3db65f"
                    "7fedea62bbf781c5410d3f22a7a3a56ffefb2238af8627363bdf2ed97c"
                    "1f89784a1aecdb43384f11d2acc64443c7fc299cef0400421a53ae"
                ),
                addrs=[
                    pkAddr(
                        ByteArray(
                            "04cb9c3c222c5f7a7d3b9bd152f363a0b6d54c9eb312c4d4f9"
                            "af1e8551b6c421a6a4ab0e29105f24de20ff463c1c91fcf3bf"
                            "662cdde4783d4799f787cb7c08869b"
                        )
                    ),
                    pkAddr(
                        ByteArray(
                            "04ccc588420deeebea22a7e900cc8b68620d2212c374604e3"
                            "487ca08f1ff3ae12bdc639514d0ec8612a2d3c519f084d9a0"
                            "0cbbe3b53d071e9b09e71e610b036aa2"
                        )
                    ),
                    pkAddr(
                        ByteArray(
                            "04ab47ad1939edcb3db65f7fedea62bbf781c5410d3f22a7a"
                            "3a56ffefb2238af8627363bdf2ed97c1f89784a1aecdb4338"
                            "4f11d2acc64443c7fc299cef0400421a"
                        )
                    ),
                ],
                reqSigs=2,
                scriptClass=txscript.MultiSigTy,
            )
        )

        # The below are nonstandard script due to things such as
        # invalid pubkeys, failure to parse, and not being of a
        # standard form.

        tests.append(
            test(
                name="p2pk with uncompressed pk missing OP_CHECKSIG",
                script=ByteArray(
                    "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a"
                    "5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
                ),
                addrs=[],
                exception="unsupported script",
            )
        )
        tests.append(
            test(
                name="valid signature from a sigscript - no addresses",
                script=ByteArray(
                    "47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd"
                    "410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"
                ),
                addrs=[],
                exception="unsupported script",
            )
        )
        # Note the technically the pubkey is the second item on the
        # stack, but since the address extraction intentionally only
        # works with standard PkScripts, this should not return any
        # addresses.
        tests.append(
            test(
                name="valid sigscript to redeem p2pk - no addresses",
                script=ByteArray(
                    "493046022100ddc69738bf2336318e4e041a5a77f305da87428ab1606"
                    "f023260017854350ddc022100817af09d2eec36862d16009852b7e3a0"
                    "f6dd76598290b7834e1453660367e07a014104cd4240c198e12523b6f"
                    "9cb9f5bed06de1ba37e96a1bbd13745fcf9d11c25b1dff9a519675d19"
                    "8804ba9962d3eca2d5937d58e5a75a71042d40388a4d307f887d"
                ),
                addrs=[],
                reqSigs=0,
                exception="unsupported script",
            )
        )
        # adapted from btc:
        # tx 691dd277dc0e90a462a3d652a1171686de49cf19067cd33c7df0392833fb986a, vout 0
        # invalid public keys
        tests.append(
            test(
                name="1 of 3 multisig with invalid pubkeys",
                script=ByteArray(
                    "5141042200007353455857696b696c65616b73204361626c6567617465"
                    "204261636b75700a0a6361626c65676174652d32303130313230343138"
                    "31312e377a0a0a446f41046e6c6f61642074686520666f6c6c6f77696e"
                    "67207472616e73616374696f6e732077697468205361746f736869204e"
                    "616b616d6f746f277320646f776e6c6f61410420746f6f6c2077686963"
                    "680a63616e20626520666f756e6420696e207472616e73616374696f6e"
                    "2036633533636439383731313965663739376435616463636453ae"
                ),
                addrs=[],
                exception="isn't on secp256k1 curve",
            )
        )
        # adapted from btc:
        # tx 691dd277dc0e90a462a3d652a1171686de49cf19067cd33c7df0392833fb986a, vout 44
        # invalid public keys
        tests.append(
            test(
                name="1 of 3 multisig with invalid pubkeys 2",
                script=ByteArray(
                    "514104633365633235396337346461636536666430383862343463656"
                    "638630a63363662633139393663386239346133383131623336353631"
                    "386665316539623162354104636163636539393361333938386134363"
                    "966636336643664616266640a32363633636661396366346330336336"
                    "303963353933633365393166656465373032392102323364643432643"
                    "235363339643338613663663530616234636434340a00000053ae"
                ),
                addrs=[],
                exception="isn't on secp256k1 curve",
            )
        )
        tests.append(
            test(
                name="empty script",
                script=ByteArray(b""),
                addrs=[],
                reqSigs=0,
                exception="unsupported script",
            )
        )
        tests.append(
            test(
                name="script that does not parse",
                script=ByteArray([opcode.OP_DATA_45]),
                addrs=[],
                reqSigs=0,
                exception="unsupported script",
            )
        )

        def checkAddrs(a, b, name):
            if len(a) != len(b):
                t.fail(
                    "extracted address length mismatch. expected %d, got %d"
                    % (len(a), len(b))
                )
            for av, bv in zip(a, b):
                if av.scriptAddress() != bv.scriptAddress():
                    self.fail(
                        "scriptAddress mismatch. expected %s, got %s (%s)"
                        % (av.scriptAddress().hex(), bv.scriptAddress().hex(), name)
                    )

        for i, t in enumerate(tests):
            try:
                scriptClass, addrs, reqSigs = txscript.extractPkScriptAddrs(
                    scriptVersion, t.script, mainnet
                )
            except Exception as e:
                if t.exception and t.exception in str(e):
                    continue
                self.fail("extractPkScriptAddrs #%d (%s): %s" % (i, t.name, e))

            self.assertEqual(scriptClass, t.scriptClass, t.name)

            self.assertEqual(reqSigs, t.reqSigs, t.name)

            checkAddrs(t.addrs, addrs, t.name)

    def test_pay_to_addr_script(self):
        """
        test_pay_to_addr_script ensures the PayToAddrScript function generates
        the correct scripts for the various types of addresses.
        """
        # 1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX
        p2pkhMain = crypto.newAddressPubKeyHash(
            ByteArray("e34cce70c86373273efcc54ce7d2a491bb4a0e84"),
            mainnet,
            crypto.STEcdsaSecp256k1,
        )

        # Taken from transaction:
        # b0539a45de13b3e0403909b8bd1a555b8cbe45fd4e3f3fda76f3a5f52835c29d
        p2shMain = crypto.newAddressScriptHashFromHash(
            ByteArray("e8c300c87986efa84c37c0519929019ef86eb5b4"), mainnet
        )

        # # disabled until Schnorr signatures implemented
        # # mainnet p2pk 13CG6SJ3yHUXo4Cr2RY4THLLJrNFuG3gUg
        # p2pkCompressedMain = crypto.newAddressPubKey(ByteArray(
        #     "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"),
        #     mainnet)

        p2pkCompressed2Main = crypto.AddressSecpPubKey(
            ByteArray(
                "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"
            ),
            mainnet,
        )

        p2pkUncompressedMain = crypto.AddressSecpPubKey(
            ByteArray(
                "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5"
                "cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
            ),
            mainnet,
        )
        # Set the pubkey compressed. See golang TestPayToAddrScript in
        # dcrd/tscript/standard_test.go
        p2pkUncompressedMain.pubkeyFormat = crypto.PKFCompressed

        class BogusAddress(crypto.AddressPubKeyHash):
            pass

        bogusAddress = (
            ByteArray(0x0000),
            ByteArray("e34cce70c86373273efcc54ce7d2a491bb4a0e84"),
            crypto.STEcdsaSecp256k1,
        )

        # Errors used in the tests below defined here for convenience and to
        # keep the horizontal test size shorter.
        class test:
            def __init__(self, inAddr, expected, err):
                self.inAddr = inAddr
                self.expected = expected
                self.err = err

        tests = [
            # pay-to-pubkey-hash address on mainnet 0
            test(
                p2pkhMain,
                "DUP HASH160 DATA_20 0xe34cce70c86373273efcc54ce7d2a491bb4a0e8488 CHECKSIG",
                False,
            ),
            # pay-to-script-hash address on mainnet 1
            test(
                p2shMain,
                "HASH160 DATA_20 0xe8c300c87986efa84c37c0519929019ef86eb5b4 EQUAL",
                False,
            ),
            # disabled until Schnorr signatures implemented
            # pay-to-pubkey address on mainnet. compressed key. 2
            # test(
            #     p2pkCompressedMain,
            #     (
            #         "DATA_33"
            #         " 0x02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"
            #         " CHECKSIG"
            #     ),
            #     False,
            # ),
            # pay-to-pubkey address on mainnet. compressed key (other way). 3
            test(
                p2pkCompressed2Main,
                (
                    "DATA_33"
                    " 0x03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"
                    " CHECKSIG"
                ),
                False,
            ),
            # pay-to-pubkey address on mainnet. for Decred this would
            # be uncompressed, but standard for Decred is 33 byte
            # compressed public keys.
            test(
                p2pkUncompressedMain,
                (
                    "DATA_33"
                    " 0x0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cac"
                ),
                False,
            ),
            # Unsupported address type.
            test(bogusAddress, "", True),
        ]

        for t in tests:
            try:
                pkScript = txscript.payToAddrScript(t.inAddr)
            except Exception as e:
                if not t.err:
                    self.fail("unexpected exception: %s" % e)
                continue

            self.assertEqual(pkScript, parseShortForm(t.expected))

    def test_script_class(self):
        """
        test_script_class ensures all the scripts in scriptClassTests have the expected
        class.
        """
        scriptVersion = 0
        for test in scriptClassTests():
            script = parseShortForm(test.script)
            scriptClass = txscript.getScriptClass(scriptVersion, script)
            self.assertEqual(scriptClass, test.scriptClass, test.name)

    def test_calc_signature_hash_reference(self):
        """
        test_calc_signature_hash_reference runs the reference signature hash calculation
        tests in sighash.json.
        """
        fileDir = os.path.dirname(os.path.realpath(__file__))
        path = os.path.join(fileDir, "test-data", "sighash.json")
        with open(path, "r") as f:
            tests = json.loads(f.read())

        scriptVersion = 0
        for i, test in enumerate(tests):
            # raw transaction, script, input index, hash type, signature hash (result),
            # expected error, comment (optional)

            # Skip comment lines.
            if len(test) == 1:
                continue

            if len(test) == 6:
                txHex, scriptHex, vin, hashType, sigHashHex, err = test
            elif len(test) == 7:
                txHex, scriptHex, vin, hashType, sigHashHex, err, comment = test
            else:
                raise Exception("Test #%d: wrong length %d" % (i, len(test)))

            # Extract and parse the transaction from the test fields.
            tx = msgtx.MsgTx.deserialize(ByteArray(txHex))

            # Extract and parse the script from the test fields.
            subScript = ByteArray(scriptHex)
            scriptErr = txscript.checkScriptParses(scriptVersion, subScript)
            if scriptErr:
                self.fail("checkScriptParses failed with error %s" % scriptErr)

            # Extract and parse the signature hash from the test fields.
            expectedHash = ByteArray(sigHashHex)

            # Calculate the signature hash and verify expected result.
            try:
                sigHash = txscript.calcSignatureHash(subScript, hashType, tx, vin, None)
            except Exception as e:
                if err == "OK":
                    self.fail("unexpected calcSignatureHash exception: %s" % e)
                continue

            self.assertEqual(sigHash, expectedHash)

    def test_scriptNumBytes(self):
        tests = [
            (0, ByteArray()),
            (1, ByteArray("01")),
            (-1, ByteArray("81")),
            (127, ByteArray("7f")),
            (-127, ByteArray("ff")),
            (128, ByteArray("8000")),
            (-128, ByteArray("8080")),
            (129, ByteArray("8100")),
            (-129, ByteArray("8180")),
            (256, ByteArray("0001")),
            (-256, ByteArray("0081")),
            (32767, ByteArray("ff7f")),
            (-32767, ByteArray("ffff")),
            (32768, ByteArray("008000")),
            (-32768, ByteArray("008080")),
            (65535, ByteArray("ffff00")),
            (-65535, ByteArray("ffff80")),
            (524288, ByteArray("000008")),
            (-524288, ByteArray("000088")),
            (7340032, ByteArray("000070")),
            (-7340032, ByteArray("0000f0")),
            (8388608, ByteArray("00008000")),
            (-8388608, ByteArray("00008080")),
            (2147483647, ByteArray("ffffff7f")),
            (-2147483647, ByteArray("ffffffff")),
            (2147483648, ByteArray("0000008000")),
            (-2147483648, ByteArray("0000008080")),
            (2415919104, ByteArray("0000009000")),
            (-2415919104, ByteArray("0000009080")),
            (4294967295, ByteArray("ffffffff00")),
            (-4294967295, ByteArray("ffffffff80")),
            (4294967296, ByteArray("0000000001")),
            (-4294967296, ByteArray("0000000081")),
            (281474976710655, ByteArray("ffffffffffff00")),
            (-281474976710655, ByteArray("ffffffffffff80")),
            (72057594037927935, ByteArray("ffffffffffffff00")),
            (-72057594037927935, ByteArray("ffffffffffffff80")),
            (9223372036854775807, ByteArray("ffffffffffffff7f")),
            (-9223372036854775807, ByteArray("ffffffffffffffff")),
        ]

        for num, serialized in tests:
            gotBytes = txscript.scriptNumBytes(num)
            self.assertEqual(
                gotBytes,
                serialized,
                (str(num) + ": wanted " + serialized.hex() + ", got " + gotBytes.hex()),
            )


class TestVSP(unittest.TestCase):
    def test_blob(self):
        pi = vsp.PurchaseInfo(
            addr="someaddr",
            fees=1.3,
            script=ByteArray("0a1b2c"),
            ticketAddr="someotheraddr",
            vBits=2,
            vBitsVer=1,
            stamp=123456,
        )
        stakePool = vsp.VotingServiceProvider(
            "http://localhost:54321", "somerandomkey", mainnet.Name, pi
        )
        b = stakePool.serialize()
        rePool = vsp.VotingServiceProvider.unblob(b.b)
        self.assertEqual(stakePool.url, rePool.url)
        self.assertEqual(stakePool.apiKey, rePool.apiKey)
        self.assertEqual(stakePool.net.Name, rePool.net.Name)
        rePI = rePool.purchaseInfo
        self.assertEqual(pi.poolAddress, rePI.poolAddress)
        self.assertEqual(pi.poolFees, rePI.poolFees)
        self.assertEqual(pi.script, rePI.script)
        self.assertEqual(pi.ticketAddress, rePI.ticketAddress)
        self.assertEqual(pi.voteBits, rePI.voteBits)
        self.assertEqual(pi.voteBitsVersion, rePI.voteBitsVersion)
        self.assertEqual(pi.unixTimestamp, rePI.unixTimestamp)


class TestAccount(unittest.TestCase):
    def test_balance(self):
        bal = account.Balance(1, 2, 3)
        encoded = account.Balance.blob(bal)
        reBal = account.Balance.unblob(encoded)
        self.assertEqual(bal.available, reBal.available)
        self.assertEqual(bal.total, reBal.total)
        self.assertEqual(bal.staked, reBal.staked)

    def test_gap_handling(self):
        cryptoKey = ByteArray(rando.generateSeed(32))
        with TemporaryDirectory() as tempDir:
            db = database.KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
            internalAddrs = [
                "DskHpgbEb6hqkuHchHhtyojpehFToEtjQSo",
                "Dsm4oCLnLraGDedfU5unareezTNT75kPbRb",
                "DsdN6A9bWhKKJ7PAGdcDLxQrYPKEnjnDv2N",
                "Dsifz8eRHvQrfaPXgHHLMDHZopFJq2pBPU9",
                "DsmmzJiTTmpafdt2xx7LGk8ZW8cdAKe53Zx",
                "DsVB47P4N23PK5C1RyaJdqkQDzVuCDKGQbj",
                "DsouVzScdUUswvtCAv6nxRzi2MeufpWnELD",
                "DsSoquT5SiDPfksgnveLv3r524k1v8RamYm",
                "DsbVDrcfhbdLy4YaSmThmWN47xhxT6FC8XB",
                "DsoSrtGYKruQLbvhA92xeJ6eeuAR1GGJVQA",
            ]

            externalAddrs = [
                "DsmP6rBEou9Qr7jaHnFz8jTfrUxngWqrKBw",
                "DseZQKiWhN3ceBwDJEgGhmwKD3fMbwF4ugf",
                "DsVxujP11N72PJ46wgU9sewptWztYUy3L7o",
                "DsYa4UBo379cRMCTpDLxYVfpMvMNBdAGrGS",
                "DsVSEmQozEnsZ9B3D4Xn4H7kEedDyREgc18",
                "DsifDp8p9mRocNj7XNNhGAsYtfWhccc2cry",
                "DsV78j9aF8NBwegbcpPkHYy9cnPM39jWXZm",
                "DsoLa9Rt1L6qAVT9gSNE5F5XSDLGoppMdwC",
                "DsXojqzUTnyRciPDuCFFoKyvQFd6nQMn7Gb",
                "DsWp4nShu8WxefgoPej1rNv4gfwy5AoULfV",
            ]

            account.DefaultGapLimit = gapLimit = 5
            root = crypto.ExtendedKey.new(testSeed)
            coinExtKey = root.deriveCoinTypeKey(mainnet)
            acct = createAccount(
                cryptoKey, coinExtKey, 42, 0, mainnet.Name, "default", db, None
            )
            acct.gapLimit = gapLimit

            listsAreEqual = lambda a, b: len(a) == len(b) and all(
                x == y for x, y in zip(a, b)
            )

            self.assertTrue(
                listsAreEqual(acct.internalAddresses, internalAddrs[:gapLimit])
            )
            # The external branch starts with the "last seen" at the zeroth address, so
            # has one additional address to start.
            self.assertTrue(
                listsAreEqual(acct.externalAddresses, externalAddrs[: gapLimit + 1])
            )

            # Open the account to generate addresses.
            acct.open(cryptoKey, None, None)
            acct.addTxid(internalAddrs[0], "C4fA6958A1847D")
            newAddrs = acct.generateGapAddresses()
            self.assertEqual(len(newAddrs), 1)
            self.assertEqual(newAddrs[0], internalAddrs[5])

            # The zeroth external address is considered "seen", so this should not
            # change anything.
            acct.addTxid(externalAddrs[0], "C4fA6958A1847D")
            newAddrs = acct.generateGapAddresses()
            self.assertEqual(len(newAddrs), 0)

            # Mark the 1st address as seen.
            acct.addTxid(externalAddrs[1], "C4fA6958A1847D")
            newAddrs = acct.generateGapAddresses()
            self.assertEqual(len(newAddrs), 1)
            self.assertEqual(externalAddrs[1], acct.currentAddress())

            # cursor should be at index 0, last seen 1, max index 6, so calling
            # nextExternalAddress 5 time should put the cursor at index 6, which is
            # the gap limit.
            for i in range(5):
                acct.nextExternalAddress()
            self.assertEqual(acct.currentAddress(), externalAddrs[6])

            # one more should wrap the cursor back to 1, not zero, so the current
            # address is lastSeenExt(=1) + cursor(=1) = 2
            a1 = acct.nextExternalAddress()
            self.assertEqual(acct.currentAddress(), externalAddrs[2])
            self.assertEqual(a1, acct.currentAddress())

            # Sanity check that internal addresses are wrapping too.
            for i in range(20):
                acct.nextInternalAddress()
            addrs = acct.internalAddresses
            self.assertEqual(addrs[len(addrs) - 1], internalAddrs[5])

    def test_account(self):
        """
        Test account functionality.
        """
        cryptoKey = crypto.ByteArray(rando.generateSeed(32))
        with TemporaryDirectory() as tempDir:
            db = database.KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
            root = crypto.ExtendedKey.new(testSeed)
            coinExtKey = root.deriveCoinTypeKey(mainnet)
            acct = createAccount(
                cryptoKey, coinExtKey, 42, 0, mainnet.Name, "default", db, None
            )
            for n in range(20):
                acct.nextExternalAddress()
            satoshis = int(round(5 * 1e8))
            txHash = ByteArray(rando.generateSeed(32))
            txid = reversed(txHash).hex()
            vout = 2
            address = acct.nextExternalAddress()

            utxo = account.UTXO(
                address=address,
                txHash=txHash,
                vout=vout,
                scriptPubKey=ByteArray(0),
                satoshis=satoshis,
                maturity=1,
            )

            # A helper function to get the current utxo count.
            utxocount = lambda: len(list(acct.utxoscan()))

            # Add the utxo
            acct.addUTXO(utxo)
            # Check the count and balance categories.
            self.assertEqual(utxocount(), 1)
            self.assertEqual(acct.calcBalance(1).total, satoshis)
            self.assertEqual(acct.calcBalance(1).available, satoshis)
            self.assertEqual(acct.calcBalance(0).available, 0)
            # Helper functions.
            self.assertTrue(acct.caresAboutTxid(txid))
            acct.addUTXO(utxo)
            self.assertEqual(utxocount(), 1)
            acct.spendUTXO(utxo)
            self.assertEqual(utxocount(), 0)

            b = acct.serialize()
            reAcct = account.Account.unblob(b.b)

            self.assertEqual(acct.pubKeyEncrypted, reAcct.pubKeyEncrypted)
            self.assertEqual(acct.privKeyEncrypted, reAcct.privKeyEncrypted)
            self.assertEqual(acct.name, reAcct.name)
            self.assertEqual(acct.coinID, reAcct.coinID)
            self.assertEqual(acct.netID, reAcct.netID)
            self.assertEqual(acct.gapLimit, reAcct.gapLimit)
            self.assertEqual(acct.cursorExt, reAcct.cursorExt)
            self.assertEqual(acct.cursorInt, reAcct.cursorInt)
            self.assertEqual(acct.gapLimit, reAcct.gapLimit)

    def test_tiny_block(self):
        blockHash = newHash()
        height = 55
        TinyBlock = account.TinyBlock
        tb1 = TinyBlock(blockHash, height)
        tb2 = TinyBlock.parse({"hash": blockHash, "height": height,})
        self.assertEqual(tb1.hash, tb2.hash)
        self.assertEqual(tb1.height, tb2.height)

        b = tb1.serialize()
        reTB = TinyBlock.unblob(b)
        self.assertEqual(tb1.hash, reTB.hash)
        self.assertEqual(tb1.height, reTB.height)

    def test_ticket_info(self):
        TicketInfo = account.TicketInfo
        TinyBlock = account.TinyBlock
        # First try with all zero values
        tktNfo = TicketInfo(
            status="",
            purchaseBlock=None,
            maturityHeight=0,
            expirationHeight=0,
            lotteryBlock=None,
            vote=None,
            revocation=None,
        )

        b = tktNfo.serialize()
        reNfo = TicketInfo.unblob(b.b)

        def check():
            self.assertEqual(tktNfo.status, reNfo.status)
            self.assertEqual(tktNfo.purchaseBlock, reNfo.purchaseBlock)
            self.assertEqual(tktNfo.maturityHeight, reNfo.maturityHeight)
            self.assertEqual(tktNfo.expirationHeight, reNfo.expirationHeight)
            self.assertEqual(tktNfo.lotteryBlock, reNfo.lotteryBlock)
            self.assertEqual(tktNfo.vote, reNfo.vote)
            self.assertEqual(tktNfo.revocation, reNfo.revocation)

        check()

        tktNfo = TicketInfo(
            status="immature",
            purchaseBlock=TinyBlock(newHash(), 55),
            maturityHeight=500,
            expirationHeight=1000,
            lotteryBlock=TinyBlock(newHash(), 66),
            vote=newHash(),
            revocation=newHash(),
        )

        b = tktNfo.serialize()
        reNfo = TicketInfo.unblob(b.b)

        check()

    def test_utxo(self):
        UTXO = account.UTXO
        TicketInfo = account.TicketInfo
        TinyBlock = account.TinyBlock
        address = "someaddressanyaddress"
        txHash = newHash()
        vout = 55

        utxo = UTXO(address=address, txHash=txHash, vout=vout,)

        b = utxo.serialize()
        reUTXO = UTXO.unblob(b.b)

        def check():
            self.assertEqual(utxo.address, reUTXO.address)
            self.assertEqual(utxo.txHash, reUTXO.txHash)
            self.assertEqual(utxo.vout, reUTXO.vout)
            self.assertEqual(utxo.ts, reUTXO.ts)
            self.assertEqual(utxo.scriptPubKey, reUTXO.scriptPubKey)
            self.assertEqual(utxo.height, reUTXO.height)
            self.assertEqual(utxo.amount, reUTXO.amount)
            self.assertEqual(utxo.satoshis, reUTXO.satoshis)
            self.assertEqual(utxo.maturity, reUTXO.maturity)
            self.assertEqual(utxo.scriptClass, reUTXO.scriptClass)
            if utxo.tinfo:
                self.assertEqual(utxo.tinfo.serialize(), reUTXO.tinfo.serialize())

        check()

        tktNfo = TicketInfo(
            status="immature",
            purchaseBlock=TinyBlock(newHash(), 55),
            maturityHeight=500,
            expirationHeight=1000,
            lotteryBlock=TinyBlock(newHash(), 66),
            vote=newHash(),
            revocation=newHash(),
        )

        utxo = UTXO(
            address,
            txHash,
            vout,
            ts=int(time.time()),
            scriptPubKey=newHash(),
            height=560,
            satoshis=5000000,
            maturity=55,
            tinfo=tktNfo,
        )

        b = utxo.serialize()
        reUTXO = UTXO.unblob(b.b)

        check()
