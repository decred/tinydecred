"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.dcr.wire import wire
from decred.util.encode import ByteArray


class TestWire:
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

    def test_write_var_int(self, prepareLogger):
        for val, bytes_ in self.data:
            from_val = wire.writeVarInt(wire.ProtocolVersion, val)
            from_bytes = ByteArray(bytes_)
            assert from_val == from_bytes
            val_from_bytes = wire.readVarInt(from_bytes, wire.ProtocolVersion)
            assert val_from_bytes == val
        with pytest.raises(DecredError):
            wire.writeVarInt(wire.ProtocolVersion, wire.MaxUint64 + 1)

    def test_read_var_int(self, prepareLogger):
        assert wire.readVarInt(ByteArray([0xFC]), wire.ProtocolVersion) == 0xFC
        with pytest.raises(DecredError):
            wire.readVarInt(
                ByteArray([0xFE, 0xFF, 0xFF, 0x0, 0x0]),
                wire.ProtocolVersion
            )
            wire.readVarInt(
                ByteArray([0xFD, 0xFC, 0x0]),
                wire.ProtocolVersion
            )
