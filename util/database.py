"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

Blobber API:
    A Blobber is a class that byte-encodes and decodes a specific type. The two
    methods required of a Blobber are 

    blob(obj)
        obj: an instance of the object for the blobber to encode.

    unblob(b):
        b: bytes to decode into an instance the Blobber's class
"""

import sqlite3
import threading

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
        self.conn = SequencedConection(self.filepath, check_same_thread=False)
    def child(self, name, **k):
        return Bucket(self.conn, name, **k)
    def close(self):
        self.conn.close()

class Bucket:
    def __init__(self, conn, name, datatypes=("BLOB", "BLOB"), unique=True, blobber=None):
        self.conn = conn
        self.name = name
        self.blobber = blobber
        self.lock = threading.Lock()
        self.createQuery = KVTable.format(
            tablename=name, keytype=datatypes[0], valuetype=datatypes[1]
        )
        if unique:
            self.indexQuery = KVUniqueIndex.format(tablename=name)
        else:
            self.indexQuery = KVIndex.format(tablename=name)
        self.getQuery = KVGet.format(
            tablename=name
        )  # = "SELECT v FROM kvtable WHERE k = ?;"
        self.setQuery = KVSet.format(
            tablename=name
        )  # = "REPLACE INTO kvtable(k, v) VALUES(?, ?);"
        self.existsQuery = KVExists.format(
            tablename=name
        )  # = "SELECT EXISTS(SELECT * FROM kvtable WHERE k = ?);"
        self.deleteQuery = KVDelete.format(
            tablename=name
        )  # = "DELETE FROM kvtable WHERE k = ?;"
        self.countQuery = KVCount.format(
            tablename=name
        )  # = "SELECT COUNT(*) FROM kvtable;"
        self.open()

    def open(self):
        cursor = self.conn.cursor()
        cursor.execute(self.createQuery)
        cursor.execute(self.indexQuery)
        self.conn.commit()

    def child(self, name, **k):
        if "$" in name:
            raise Exception("illegal character. '$' not allowed in table name")
        compoundName = "{parent}${child}".format(parent=self.name, child=name)
        return Bucket(self.conn, compoundName, **k)

    def __setitem__(self, k, v):
        self.conn.lock()
        print("--setting")
        try:
            if self.blobber:
                print("--blobbing")
                v = self.blobber.blob(v)
            cursor = self.conn.cursor()
            cursor.execute(self.setQuery, (k, v))
            self.conn.commit()
        finally:
            self.conn.unlock()

    def __getitem__(self, k):
        cursor = self.conn.cursor()
        cursor.execute(self.getQuery, (k,))
        row = cursor.fetchone()
        if row is None:
            raise NO_VALUE_EXCEPTION
        if not self.blobber:
            return row[0]
        return self.blobber.unblob(row[0])

    def __delitem__(self, k):
        self.conn.lock()
        try:
            cursor = self.conn.cursor()
            cursor.execute(self.deleteQuery, (k,))
            self.conn.commit()
        finally:
            self.conn.unlock()

    def __contains__(self, k):
        cursor = self.conn.cursor()
        cursor.execute(self.existsQuery, (k,))
        row = cursor.fetchone()
        if row is None:
            return False
        return row[0] == 1

    def __len__(self):
        cursor = self.conn.cursor()
        cursor.execute(self.countQuery)
        row = cursor.fetchone()
        if row is None:
            return 0
        return row[0]

class SequencedConection(sqlite3.Connection):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.mtx = threading.Lock()
    def lock(self):
        self.mtx.acquire()
    def unlock(self):
        self.mtx.release()