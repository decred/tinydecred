"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred.decred.util import database


@pytest.fixture
def setup_db(tmpdir):
    # Open a key value db in the temp directory.
    db = database.KeyValueDatabase(tmpdir.join("bm.sqlite")).child("testdb")
    # Generate some data.
    return db, [(str(i).encode(), str(i).encode()) for i in range(10)]


def test_insert(setup_db, benchmark):
    def insert(db, data):
        for k, v in data:
            db[k] = v

    db, data = setup_db
    benchmark(insert, db, data)
    assert len(db) == len(data)


def test_clear(setup_db, benchmark):
    db, data = setup_db
    db.batchInsert(data)
    benchmark(db.clear)
    assert len(db) == 0


def test_batchInsert(setup_db, benchmark):
    db, data = setup_db
    benchmark(db.batchInsert, data)
    assert len(db) == len(data)
