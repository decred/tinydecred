"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os.path
from tempfile import TemporaryDirectory
import time

import pytest

from decred.util import database


def test_benchmark():
    with TemporaryDirectory() as tempDir:

        # Open a key value db in the temp directory.
        master = database.KeyValueDatabase(os.path.join(tempDir, "bm.sqlite"))
        db = master.child("testdb")
        # run some benchmarks
        num = 100
        print(f"\nrunning benchmark with {num} values")

        data = [(str(i).encode(), str(i).encode()) for i in range(num)]

        start = time.time()

        def lap(tag):
            nonlocal start
            elapsed = (time.time() - start) * 1000
            print(f"{tag}: {int(elapsed)} ms")
            start = time.time()

        for k, v in data:
            db[k] = v
        assert len(db) == num
        lap("insert")

        db.clear()
        assert len(db) == 0
        lap("clear")

        db.batchInsert(data)
        assert len(db) == num
        lap("batch insert")

        with pytest.raises(database.NoValueError):
            db["nonsense"]
