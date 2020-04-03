"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import time

import pytest

from decred.util import database


def test_benchmark(tmpdir, capsys):
    # Open a key value db in the temp directory.
    db = database.KeyValueDatabase(tmpdir.join("bm.sqlite")).child("testdb")
    # run some benchmarks
    num = 100
    with capsys.disabled():
        print(f"\nrunning benchmark with {num} values")

    data = [(str(i).encode(), str(i).encode()) for i in range(num)]

    start = time.time()

    def lap(tag):
        nonlocal start
        elapsed = (time.time() - start) * 1000
        with capsys.disabled():
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
