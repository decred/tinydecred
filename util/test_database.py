"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest
import os
from tinydecred.util import database
from tinydecred.util import helpers

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

			# Encode it to bytes.
			for kv in testPairs:
				kv[0] = kv[0].encode()
				kv[1] = kv[1].encode()

			# Open a key value db in the temp directory.
			manager = database.KeyValueDatabase(os.path.join(tempDir, 'tmp.sqlite'))
			with manager.getBucket("test") as db:

				# Ensure the db has zero length.
				self.assertTrue(len(db) == 0)

				# Insert the test pairs.
				for k, v in testPairs:
					db[k] = v

				# Check length again
				self.assertTrue(len(db) == len(testPairs))

				# Delete an item
				outPair = db[testPairs[0][0]]
				del db[testPairs[0][0]]
				# Check the length again
				self.assertTrue(len(db) == len(testPairs) - 1)

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
				self.assertTrue(len(db) == 0)

				# Insert again
				for k, v in testPairs:
					db[k] = v

				# Make sure nothing has changed. 
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
			with manager.getBucket("inttest", datatypes=("INTEGER", "BLOB")) as db:
				db[5] = b'asdf'
				self.assertEqual(db[5], b'asdf')
