"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from decred.dcr.wire import wire
from decred.util import helpers
from decred.util.encode import ByteArray


class TestWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.prepareLogger("TestWire")

    def test_write_read_var_int(self):
        # fmt: off
        data = (
            (0xFC,               [0xFC]),
            (0xFD,               [0xFD, 0xFD, 0x0]),
            (wire.MaxUint16,     [0xFD, 0xFF, 0xFF]),
            (wire.MaxUint16 + 1, [0xFE, 0x0,  0x0,  0x1,  0x0]),
            (wire.MaxUint32,     [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
            (wire.MaxUint32 + 1, [0xFF, 0x0,  0x0,  0x0,  0x0,  0x1,  0x0,  0x0,  0x0]),
            (wire.MaxUint64,     [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        )
        # fmt: on
        for val, bytes_ in data:
            from_val = wire.writeVarInt(wire.ProtocolVersion, val)
            from_bytes = ByteArray(bytes_)
            self.assertEqual(from_val, from_bytes)
            val_from_bytes = wire.readVarInt(from_bytes, wire.ProtocolVersion)
            self.assertEqual(val_from_bytes, val)
        self.assertRaises(
            ValueError, wire.writeVarInt, wire.ProtocolVersion, wire.MaxUint64 + 1
        )
        self.assertEqual(wire.readVarInt(ByteArray([0xFC]), wire.ProtocolVersion), 0xFC)
