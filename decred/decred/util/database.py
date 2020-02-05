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

KVUniqueIndex = "CREATE UNIQUE INDEX IF NOT EXISTS idx_{tablename} ON {tablename}(k);"

KVIndex = "CREATE INDEX IF NOT EXISTS idx_{tablename} ON {tablename}(k);"

KVGet = "SELECT v FROM {tablename} WHERE k = ?;"

KVSet = "REPLACE INTO {tablename}(k, v) VALUES(?, ?);"

KVExists = "SELECT EXISTS(SELECT * FROM {tablename} WHERE k = ?);"

KVDelete = "DELETE FROM {tablename} WHERE k = ?;"

KVDeleteAll = "DELETE FROM {tablename};"

KVCount = "SELECT COUNT(*) FROM {tablename};"

KVKeys = "SELECT k FROM {tablename};"

KVRows = "SELECT k, v FROM {tablename};"

KVValues = "SELECT v FROM {tablename};"


class KeyValueDatabase:
    """
    A KeyValueDatabase is a sqlite3 database specialized for two-column tables
    and byte storage. The KeyValueDatabase creates tables as Buckets, which
    use the Python data model to enable dict-like access to keys and values.
    """

    def __init__(self, filepath):
        """
        Constructor for a KeyValueDatabase.

        Args:
            filepath (str): The database file path. If the file doesn't exist,
                it will be created.
        """
        self.filepath = filepath
        self.buckets = {}
        self.conn = SequencedConnection(self.filepath, check_same_thread=False)

    def child(self, name, **k):
        """
        Creates the root Bucket.

        Args:
            name (str): The root node name.
            **k: Keyword arguments are passed directly to the Bucket
                constructor.

        Returns:
            Bucket: The root bucket.
        """
        if "$" in name:
            raise ValueError("illegal character. '$' not allowed in table name")
        return Bucket(self.conn, name, **k)

    def close(self):
        """
        Close the database.
        """
        self.conn.close()


class Bucket:
    """
    A Bucket is a node on the key-value database table tree. It may or may not
    represent a table in the database.
    """

    def __init__(
        self,
        conn,
        name,
        datatypes=("BLOB", "BLOB"),
        unique=True,
        blobber=None,
        table=True,
    ):
        """
        Constructor for a Bucket.

        Args:
            conn (SequencedConnection): The database connection.
            name (str): The Bucket name.
            datatypes (tuple(str)): optional. default ("BLOB", "BLOB"). The key
                and value data types, respectively. sqlite3 specifiers.
            unique (bool): optional. default True. Whether the keys are unique.
            blobber (encode.Blobber): optional. default does nothing. The
                Blobber.
            table (bool): optional. default True. Whether or not to create a
                table for this node. If this node is only for namespacing, a
                table may not be needed.
        """
        self.conn = conn
        self.name = name
        if not table:
            return
        self.lock = threading.Lock()
        self.encoder = blobber.blob if blobber else lambda v: v
        self.decoder = blobber.unblob if blobber else lambda v: v
        createQuery = KVTable.format(
            tablename=name, keytype=datatypes[0], valuetype=datatypes[1]
        )
        if unique:
            indexQuery = KVUniqueIndex.format(tablename=name)
        else:
            indexQuery = KVIndex.format(tablename=name)
        cursor = self.conn.cursor()
        cursor.execute(createQuery)
        cursor.execute(indexQuery)
        conn.commit()

        self.getQuery = KVGet.format(
            tablename=name
        )  # = "SELECT v FROM {tablename} WHERE k = ?;"
        self.setQuery = KVSet.format(
            tablename=name
        )  # = "REPLACE INTO {tablename}(k, v) VALUES(?, ?);"
        self.existsQuery = KVExists.format(
            tablename=name
        )  # = "SELECT EXISTS(SELECT * FROM {tablename} WHERE k = ?);"
        self.deleteQuery = KVDelete.format(
            tablename=name
        )  # = "DELETE FROM {tablename} WHERE k = ?;"
        self.deleteAllQuery = KVDeleteAll.format(
            tablename=name
        )  # = "DELETE FROM {tablename};"
        self.countQuery = KVCount.format(
            tablename=name
        )  # = "SELECT COUNT(*) FROM {tablename};"
        self.keysQuery = KVKeys.format(tablename=name)  # = "SELECT k FROM {tablename}"
        self.rowsQuery = KVRows.format(
            tablename=name
        )  # = "SELECT k, v FROM {tablename}"
        self.valuesQuery = KVValues.format(
            tablename=name
        )  # = "SELECT k, v FROM {tablename}"

    def child(self, name, **k):
        """
        Create a child Bucket, which is really just a Bucket with a name which
        derives from this Bucket's name.

        Args:
            name (str): The child Bucket name.
            **k: Keyword arguments are passed directly to the Bucket
                constructor.
        """
        if "$" in name:
            raise ValueError("illegal character. '$' not allowed in table name")
        compoundName = "{parent}${child}".format(parent=self.name, child=name)
        return Bucket(self.conn, compoundName, **k)

    def __setitem__(self, k, v):
        """dict-like assignment"""
        self.conn.lock()
        try:
            self.conn.cursor().execute(self.setQuery, (k, self.encoder(v)))
            self.conn.commit()
        finally:
            self.conn.unlock()

    def __getitem__(self, k):
        """dict-like retrieval"""
        cursor = self.conn.cursor()
        cursor.execute(self.getQuery, (k,))
        row = cursor.fetchone()
        if row is None:
            raise NO_VALUE_EXCEPTION
        return self.decoder(row[0])

    def __delitem__(self, k):
        """dict-like deletion"""
        self.conn.lock()
        try:
            self.conn.cursor().execute(self.deleteQuery, (k,))
            self.conn.commit()
        finally:
            self.conn.unlock()

    def __contains__(self, k):
        """dict-like key check using the `in` operator"""
        cursor = self.conn.cursor()
        cursor.execute(self.existsQuery, (k,))
        row = cursor.fetchone()
        if row is None:  # nocover
            return False
        return row[0] == 1

    def __len__(self):
        """Called by the `len` function"""
        cursor = self.conn.cursor()
        cursor.execute(self.countQuery)
        row = cursor.fetchone()
        if row is None:  # nocover
            return 0
        return row[0]

    def __iter__(self):
        """dict-like iteration. see also items, keys, and values"""
        for k in self.keys():
            yield k

    def keys(self):
        """
        keys iterates a Bucket keys.

        Returns:
            generator: A generator to iterate the keys.
        """
        cursor = self.conn.cursor()
        cursor.execute(self.keysQuery)
        return (k for k, in cursor.fetchall())

    def items(self):
        """
        Iterates a tuple of (key, value) pairs.

        Returns:
            generator: A generator to iterate the tuples.
        """
        cursor = self.conn.cursor()
        cursor.execute(self.rowsQuery)
        row = cursor.fetchone()
        decoder = self.decoder
        while row:
            yield row[0], decoder(row[1])
            row = cursor.fetchone()

    def values(self):
        """
        Iterates the values in a Bucket.

        Returns:
            generator: A generator to iterate the values.
        """
        cursor = self.conn.cursor()
        cursor.execute(self.valuesQuery)
        row = cursor.fetchone()
        decoder = self.decoder
        while row:
            yield decoder(row[0])
            row = cursor.fetchone()

    def clear(self):
        """
        Clear all bucket entries.
        """
        self.conn.lock()
        try:
            self.conn.cursor().execute(self.deleteAllQuery)
            self.conn.commit()
        finally:
            self.conn.unlock()

    def batchInsert(self, pairs):
        """
        Do a batch insert of the (key, value) pairs.

        Args:
            list(tuple): List of (key, value) pairs.
        """
        self.conn.lock()
        enc = self.encoder
        # Use a generator to encode the values without copying the list.
        pairs = ((k, enc(v)) for k, v in pairs)
        try:
            self.conn.cursor().executemany(self.setQuery, pairs)
            self.conn.commit()
        finally:
            self.conn.unlock()


class SequencedConnection(sqlite3.Connection):
    """
    A SequencedConnection is a sqlite3.Connection with a mutex lock.
    """

    def __init__(self, *a, **k):
        """
        Constructor for a SequencedConnection. All arguments are passed
        directly to the sqlite.Connection construtor.
        """
        super().__init__(*a, **k)
        self.mtx = threading.Lock()

    def lock(self):
        """
        Lock the database for writing.
        """
        self.mtx.acquire()

    def unlock(self):
        """
        Unlock the database for writing.
        """
        self.mtx.release()
