"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError, unblob_check


def test_unblob_check():
    data = {0: 1}
    # Unsupported version.
    with pytest.raises(NotImplementedError):
        unblob_check("test", 1, 0, data)
    # Unexpected pushes.
    with pytest.raises(DecredError):
        unblob_check("test", 0, 2, data)
    # No errors.
    assert unblob_check("test", 0, 1, data) is None
