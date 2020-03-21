"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import random

import pytest

from decred import DecredError
from decred.util import database
from decred.util.encode import ByteArray


class TBlobber:
    def __init__(self, b):
        self.b = b

    @staticmethod
    def unblob(b):
        return TBlobber(ByteArray(b))

    @staticmethod
    def blob(tb):
        """Satisfies the encode.Blobber API"""
        return tb.b.bytes()

    def __eq__(self, other):
        return self.b == other.b


def test_database(prepareLogger, randBytes):
    # Open a key value db in the temp directory.
    master = database.KeyValueDatabase(":memory:")

    # '$' in bucket name is illegal.
    with pytest.raises(DecredError):
        master.child("a$b")

    try:
        db = master.child("test")

        # Again, '$' in bucket name is illegal.
        with pytest.raises(DecredError):
            db.child("c$d")

        # Create some test data.
        random.seed(0)
        testPairs = [(randBytes(low=1), randBytes()) for _ in range(20)]
        runPairs(db, testPairs)

        # check integer keys and child naming scheme
        intdb = db.child("inttest", datatypes=("INTEGER", "BLOB"))
        assert intdb.name == "test$inttest"
        intdb[5] = b"asdf"
        assert intdb[5] == b"asdf"
        intdb[6] = b"jkl;"
        assert intdb.first() == (5, b"asdf")
        assert intdb.last() == (6, b"jkl;")

        # check uniqueness of keys:
        k = testPairs[0][0]
        db[k] = b"some new bytes"
        assert len([key for key in db if key == k]) == 1

        # test a serializable object
        randBlobber = lambda: TBlobber(ByteArray(randBytes()))
        objDB = master.child("blobber", blobber=TBlobber, unique=False)
        testPairs = [(randBytes(low=1), randBlobber()) for _ in range(20)]
        runPairs(objDB, testPairs)

        # non-uniqueness of keys
        k = testPairs[0][0]
        objDB[k] = randBlobber()
        assert len([key for key in objDB if key == k]) == 2

        # test a second-level child
        kidDB = db.child("kid")
        testPairs = [(randBytes(low=1), randBytes()) for _ in range(20)]
        runPairs(kidDB, testPairs)

        # uniqueness of table keys
        k = testPairs[0][0]
        kidDB[k] = b"some new bytes"
        assert len([key for key in kidDB if key == k]) == 1

        # slice notation
        sliceDB = db.child("slice", datatypes=("INTEGER", "TEXT"))
        n = 5
        for i in range(n):
            sliceDB[i] = str(i)
        nums = sliceDB[:n]
        assert len(nums) == 5
        assert all(i == int(s) for i, s in nums)
        assert sliceDB.last()[0] == 4

    finally:
        master.close()


def runPairs(db, testPairs):
    ogKeys = {k: v for k, v in testPairs}
    values = [v for _, v in testPairs]

    # Ensure the db has zero length.
    assert len(db) == 0

    # Insert the test pairs.
    for k, v in testPairs:
        db[k] = v

    # Check length again
    assert len(db) == len(testPairs)

    # Check items iteration
    for k, v in db.items():
        assert k in ogKeys
        assert v == ogKeys[k]

    # Check key iteration.
    for k in db:
        assert k in ogKeys
        del ogKeys[k]
    assert len(ogKeys) == 0

    # Check value iteration.
    for v in db.values():
        values.remove(v)
    assert len(values) == 0

    # Delete an item
    k = testPairs[0][0]
    del db[k]
    # Check the length again
    assert len(db) == len(testPairs) - 1

    # Make sure the right row was deleted.
    with pytest.raises(database.NoValueError):
        v = db[k]

    # Remmove the corresponding test pair from the dict.
    testPairs.pop(0)

    # Make sure the rest are retrievable.
    for k, _ in testPairs:
        v = db[k]

    # Delete the rest
    for k, v in testPairs:
        del db[k]

    # Check the length
    assert len(db) == 0

    # Insert again
    for k, v in testPairs:
        db[k] = v

    # Make sure nothing has changed.
    for k, _ in testPairs:
        assert k in db

    # Clear the database, batch insert, and try again.
    db.clear()
    assert len(db) == 0
    db.batchInsert(testPairs)
    for k, _ in testPairs:
        assert k in db
