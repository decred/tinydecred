"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os.path
import random
from tempfile import TemporaryDirectory
import unittest

from decred.util import database, helpers
from decred.util.encode import ByteArray


random.seed(0)
randInt = random.randint
randByte = lambda: randInt(0, 255)


def randBytes(low=0, high=50):
    return bytes(randByte() for _ in range(randInt(low, high)))


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


class TestDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.prepareLogger("TestDB")

    def test_database(self):
        with TemporaryDirectory() as tempDir:

            # Open a key value db in the temp directory.
            master = database.KeyValueDatabase(os.path.join(tempDir, "tmp.sqlite"))

            # '$' in bucket name is illegal.
            self.assertRaises(ValueError, lambda: master.child("a$b"))

            try:
                db = master.child("test")

                # '$' in bucket name is illegal.
                self.assertRaises(ValueError, lambda: db.child("c$d"))

                # Create some test data.
                testPairs = [(randBytes(low=1), randBytes()) for _ in range(20)]
                self.runPairs(db, testPairs)

                # check integer keys and child naming scheme
                intdb = db.child("inttest", datatypes=("INTEGER", "BLOB"))
                self.assertEqual(intdb.name, "test$inttest")
                intdb[5] = b"asdf"
                self.assertEqual(intdb[5], b"asdf")

                # check uniqueness of keys:
                k = testPairs[0][0]
                db[k] = b"some new bytes"
                self.assertEqual(len([key for key in db if key == k]), 1)

                # test a serializable object
                randBlobber = lambda: TBlobber(ByteArray(randBytes()))
                objDB = master.child("blobber", blobber=TBlobber, unique=False)
                testPairs = [(randBytes(low=1), randBlobber()) for _ in range(20)]
                self.runPairs(objDB, testPairs)

                # non-uniqueness of keys
                k = testPairs[0][0]
                objDB[k] = randBlobber()
                self.assertEqual(len([key for key in objDB if key == k]), 2)

                # test a second-level child
                kidDB = db.child("kid")
                testPairs = [(randBytes(low=1), randBytes()) for _ in range(20)]
                self.runPairs(kidDB, testPairs)

                # uniqueness of table keys
                k = testPairs[0][0]
                kidDB[k] = b"some new bytes"
                self.assertEqual(len([key for key in kidDB if key == k]), 1)

            finally:
                master.close()

    def runPairs(self, db, testPairs):
        ogKeys = {k: v for k, v in testPairs}
        values = [v for _, v in testPairs]

        # Ensure the db has zero length.
        self.assertTrue(len(db) == 0)

        # Insert the test pairs.
        for k, v in testPairs:
            db[k] = v

        # Check length again
        self.assertEqual(len(db), len(testPairs))

        # Check items iteration
        for k, v in db.items():
            self.assertIn(k, ogKeys)
            self.assertEqual(v, ogKeys[k])

        # Check key iteration.
        for k in db:
            self.assertIn(k, ogKeys)
            del ogKeys[k]
        self.assertEqual(len(ogKeys), 0)

        # Check value iteration.
        for v in db.values():
            values.remove(v)
        self.assertEqual(len(values), 0)

        # Delete an item
        k = testPairs[0][0]
        del db[k]
        # Check the length again
        self.assertEqual(len(db), len(testPairs) - 1)

        # Make sure the right row was deleted.
        with self.assertRaises(database.NoValue):
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
        self.assertEqual(len(db), 0)

        # Insert again
        for k, v in testPairs:
            db[k] = v

        # Make sure nothing has changed.
        for k, _ in testPairs:
            self.assertTrue(k in db)

        # Clear the database, batch insert, and try again.
        db.clear()
        self.assertEqual(len(db), 0)
        db.batchInsert(testPairs)
        for k, _ in testPairs:
            self.assertTrue(k in db)
