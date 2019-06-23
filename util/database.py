"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details
"""
import sqlite3
import unittest
import os
import atexit
from tinydecred.util import helpers

class NoValue(Exception):
	pass

NO_VALUE_EXCEPTION = NoValue("no value")

KVTable = "CREATE TABLE IF NOT EXISTS {tablename} (k {keytype}, v {valuetype});"

KVUniqueIndex = "CREATE UNIQUE INDEX IF NOT EXISTS idx ON {tablename}(k);"

KVIndex = "CREATE INDEX IF NOT EXISTS idx ON {tablename}(k);"

KVGet = "SELECT v FROM {tablename} WHERE k = ?;"

KVSet = "REPLACE INTO {tablename}(k, v) VALUES(?, ?);"

KVExists = "SELECT EXISTS(SELECT * FROM {tablename} WHERE k = ?);"

KVDelete = "DELETE FROM {tablename} WHERE k = ?;"

KVCount = "SELECT COUNT(*) FROM {tablename};"

class KeyValueDatabase:
	def __init__(self, filepath, datatype="BLOB"):
		self.filepath = filepath
		self.buckets = {}
	def openDB(self):
		return sqlite3.connect(self.filepath)
	def getBucket(self, name, datatypes=("BLOB", "BLOB"), unique=True):
		return Bucket(self, name, datatypes, unique)

class Bucket:
	def __init__(self, database, name, datatypes, unique):
		self.database = database
		self.name = name
		self.createQuery = KVTable.format(tablename=name, keytype=datatypes[0], valuetype=datatypes[1])
		if unique:
			self.indexQuery = KVUniqueIndex.format(tablename=name)
		else:
			self.indexQuery = KVIndex.format(tablename=name)
		self.getQuery = KVGet.format(tablename=name) # = "SELECT v FROM kvtable WHERE k = ?;"
		self.setQuery = KVSet.format(tablename=name) # = "REPLACE INTO kvtable(k, v) VALUES(?, ?);"
		self.existsQuery = KVExists.format(tablename=name) # = "SELECT EXISTS(SELECT * FROM kvtable WHERE k = ?);"
		self.deleteQuery = KVDelete.format(tablename=name) # = "DELETE FROM kvtable WHERE k = ?;"
		self.countQuery = KVCount.format(tablename=name) # = "SELECT COUNT(*) FROM kvtable;"
	def __enter__(self):
		self.conn = self.database.openDB()
		self.open()
		return self
	def __exit__(self, xType, xVal, xTB):
		self.conn.close()
	def __setitem__(self, k, v):
		cursor = self.conn.cursor()
		cursor.execute(self.setQuery, (k, v))
		self.conn.commit()
	def __getitem__(self, k):
		cursor = self.conn.cursor()
		cursor.execute(self.getQuery, (k, ))
		row = cursor.fetchone()
		if row is None:
			raise NO_VALUE_EXCEPTION
		return row[0]
	def __delitem__(self, k):
		cursor = self.conn.cursor()
		cursor.execute(self.deleteQuery, (k, ))
		self.conn.commit()
	def __contains__(self, k):
		cursor = self.conn.cursor()
		cursor.execute(self.existsQuery, (k, ))
		row = cursor.fetchone()
		if row is None:
			return False
		return row[0] == 1
	def __len__(self):
		cursor = self.conn.cursor()
		cursor.execute(self.countQuery)
		row = cursor.fetchone()
		if row == None:
			return 0
		return row[0]
	def open(self):
		cursor = self.conn.cursor()
		cursor.execute(self.createQuery)
		cursor.execute(self.indexQuery)
		self.conn.commit()

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
				kv[0] = kv[0].encode("ascii")
				kv[1] = kv[1].encode("ascii")

			# Open a key value db in the temp directory.
			manager = KeyValueDatabase(os.path.join(tempDir, 'tmp.sqlite'))
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
				with self.assertRaises(NoValue):
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
					td.append([str(i).encode("ascii"), str(i).encode("ascii")])

				start = time.time()
				for k, v in td:
					db[k] = v
				elapsed = (time.time() - start) * 1000
				print("{} ms to insert {} values".format(num, elapsed))
				self.assertRaises(NoValue, lambda: db["nonsense"])
	





