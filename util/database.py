"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details
"""
import sqlite3
import os
from threading import get_ident as threadID
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
		self.conn = None
	def __enter__(self):
		"""
		Create a new connection for a every requesting thread.
		"""
		if self.conn:
			self.conn.close()
		self.conn = self.database.openDB()
		self.open()
		return self
	def __exit__(self, xType, xVal, xTB):
		if self.conn:
			self.conn.close()
		self.conn = None
		pass
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
