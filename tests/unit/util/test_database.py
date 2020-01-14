"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os.path
import unittest

from tinydecred.util import database
from tinydecred.util import helpers
from tinydecred.util.encode import ByteArray


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


class TestDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.prepareLogger("TestDB")

    def test_database(self):
        from tempfile import TemporaryDirectory
        import time

        with TemporaryDirectory() as tempDir:
            # Create some test data.
            testPairs = [
                ["abc", "def"],
                ["ghi", "jkl"],
                ["mno", "pqr"],
                ["stu", "vwx"],
            ]

            # Encode it to bytes. Create a dicgt of keys to compare along the
            # way.
            ogKeys = {}
            for kv in testPairs:
                kv[0] = kv[0].encode()
                kv[1] = kv[1].encode()
                ogKeys[kv[0]] = kv[1]

            # Open a key value db in the temp directory.
            master = database.KeyValueDatabase(os.path.join(tempDir, "tmp.sqlite"))
            try:
                db = master.child("test")

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

                # Delete an item
                outPair = db[testPairs[0][0]]
                del db[testPairs[0][0]]
                # Check the length again
                self.assertEqual(len(db), len(testPairs) - 1)

                # Make sure the right row was deleted.
                with self.assertRaises(database.NoValue):
                    v = db[outPair[0]]

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

                # run some benchmarks
                td = []
                num = 100
                for i in range(num):
                    td.append([str(i).encode(), str(i).encode()])

                start = time.time()
                for k, v in td:
                    db[k] = v
                elapsed = (time.time() - start) * 1000
                print("{} ms to insert {} values".format(num, elapsed))
                self.assertRaises(database.NoValue, lambda: db["nonsense"])

                # test a serializable object
                objDB = master.child("blobber", blobber=TBlobber)
                thing = TBlobber(ByteArray("a1b2c3d4e5f6"))
                k = bytearray([0xAA, 0xBB])
                objDB[k] = thing
                reThing = objDB[k]
                self.assertEqual(thing.b.hex(), reThing.b.hex())

                # check integer keys and child naming scheme
                intdb = db.child("inttest", datatypes=("INTEGER", "BLOB"))
                self.assertEqual(intdb.name, "test$inttest")
                intdb[5] = b"asdf"
                self.assertEqual(intdb[5], b"asdf")
            finally:
                master.close()
