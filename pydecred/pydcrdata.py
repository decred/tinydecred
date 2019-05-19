"""
pyDcrData
DcrDataClient.endpointList() for available enpoints.
Arguments can be positional or keyword, not both.
"""
from pydecred import helpers
import urllib.request as urlrequest
import traceback
import json
import time
import calendar
import sqlite3
import psycopg2

VERSION = "0.0.1"
HEADERS = {"User-Agent": "PyDcrData/%s" % VERSION}


def getUri(uri):
    try:
        req = urlrequest.Request(uri, headers=HEADERS, method="GET")
        raw = urlrequest.urlopen(req).read().decode()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # A couple of paths return simple strings or integers. block/best/hash or block/best/height for instance.
            return raw
        except Exception as e:
            raise DcrDataException("JSONError", "Failed to decode server response from path %s: %s : %s : %s" % (uri, raw, repr(e), traceback.print_tb(e.__traceback__)))
    except Exception as e:
        raise DcrDataException("RequestError", "Error encountered in requesting path %s: %s : %s" % (uri, repr(e), traceback.print_tb(e.__traceback__)))


class DatabaseTable:
    def __init__(self, name):
        self.name = name
        self.columns = []
        self.foreignKeys = []
        self.primaryKey = None
        # self.uniqueKeys = []
        self.uniqueIndices = []

    def addColumn(self, name, dataType, notNull=False, autoIncrement=False, default=None):
        column = {}
        column['name'] = name
        column['type'] = dataType
        column['notNull'] = notNull
        column['autoIncrement'] = autoIncrement
        column['default'] = default
        self.columns.append(column)

    def addForeignKey(self, column, otherTable, otherColumn):
        self.foreignKeys.append((column, otherTable, otherColumn))

    def addPrimaryKey(self, key):
        self.primaryKey = key

    def addUniqueKey(self, *keys):
        return self.addUniqueIndex(*keys)

    def addUniqueIndex(self, *indices):
        self.uniqueIndices.append(indices)


class DcrDataPath:
    """
    DcrDataPath represents some point along a URL. It may just be a node that
    is not an endpoint, or it may be an enpoint, in which case it's `get`
    method will be a valid api call. If it is a node of a longer URL,
    the following nodes are available as attributes. e.g. if this is node A
    along the URL base/A/B, then node B is available as client.A.B.
    """
    def __init__(self):
        self.subpaths = {}
        self.callSigns = []

    def getSubpath(self, subpathPart):
        if subpathPart in self.subpaths:
            return self.subpaths[subpathPart]
        p = self.subpaths[subpathPart] = DcrDataPath()
        return p

    def addCallsign(self, argList, template):
        """
        Some paths have multiple call signatures or optional parameters.
        Keeps a list of arguments associated with path templates to
        differentiate.
        """
        self.callSigns.append((argList, template))

    def getCallsignPath(self, *args, **kwargs):
        """
        Find the path template that matches the passed arguments.
        """
        argLen = len(args) if args else len(kwargs)
        for argList, template in self.callSigns:
            if len(argList) != argLen:
                continue
            if args:
                return template % args
            if all([x in kwargs for x in argList]):
                return template % tuple(kwargs[x] for x in argList)
        raise DcrDataException(
            "ArgumentError",
            "Supplied arguments, %r, do not match any of the know call signatures, %r." %
            (args if args else kwargs, [argList for argList, _ in self.callSigns])
        )

    def __getattr__(self, key):
        if key in self.subpaths:
            return self.subpaths[key]
        raise DcrDataException("SubpathError", "No subpath %s found in datapath with template %s" % (key, self.template))

    def __call__(self, *args, **kwargs):
        return getUri(self.getCallsignPath(*args, **kwargs))


class DcrDataClient:
    """
    DcrDataClient represents the base node. The only argument to the
    constructor is the path to a DCRData server,
    e.g. http://explorer.dcrdata.org.
    """
    timeFmt = "%Y-%m-%d %H:%M:%S"

    def __init__(self, baseUri):
        """
        Build the DcrDataPath tree.
        """
        self.baseUri = baseUri.rstrip('/').rstrip("/api") + "/api"
        root = self.root = DcrDataPath()
        self.listEntries = []
        # /list returns a json list of endpoints with parameters in template format, base/A/{param}/B
        endpoints = getUri(self.baseUri + "/list")

        def getParam(part):
            if part.startswith('{') and part.endswith('}'):
                return part[1:-1]
            return None
        pathlog = []
        for path in endpoints:
            path = path.rstrip("/")
            if path in pathlog or path == "":
                continue
            pathlog.append(path)
            params = []
            pathSequence = []
            templateParts = []
            # split the path into an array for nodes and an array for pararmeters
            for i, part in enumerate(path.strip('/').split('/')):
                param = getParam(part)
                if param:
                    params.append(param)
                    templateParts.append("%s")
                else:
                    pathSequence.append(part)
                    templateParts.append(part)
            pathPointer = root
            for pathPart in pathSequence:
                pathPointer = pathPointer.getSubpath(pathPart)
            pathPointer.addCallsign(params, "/".join([self.baseUri] + templateParts))
            if len(pathSequence) == 1:
                continue
            self.listEntries.append(("%s.get(%s)" % (".".join(pathSequence), ", ".join(params)), path))

    def __getattr__(self, key):
        return getattr(self.root, key)

    def endpointList(self):
        return [entry[1] for entry in self.listEntries]

    def endpointGuide(self):
        """
        Print on endpoint per line.
        Each line shows a translation from Python notation to a URL.
        """
        print("\n".join(["%s  ->  %s" % entry for entry in self.listEntries]))
    @staticmethod
    def timeStringToUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, DcrDataClient.timeFmt))


class DcrDataException(Exception):
    def __init__(self, name, message):
        self.name = name
        self.message = message


class Archivist:
    """
    Database stuff
    """
    def __init__(self, logger):
        self.logger = logger if logger else helpers.DefaultLogger()
        self.printQuerys = False
        self.tables = []
        self.connect()

    def connect(self):
        print("Archivist.connect must be implemented in subclass.")

    def errorParams(self, query, err):
        """
        Generate a standard set of ArchiveError parameters from a query
        and error
        """
        name = type(err).__name__
        message = (
            "An {errorType} exception occured when trying to perform the query {query}. \n"
            "The following error data was returned \n {args} : {traceback}"
            ).format(
            errorType=name,
            query=query,
            args=err.args,
            traceback=traceback.print_tb(err.__traceback__)
        )
        return name, message

    def unimplimented(self, functionName):
        return "UNIMPLEMENTED", "%s must be implemented in an inheriting class"

    def addTable(self, table):
        self.tables.append(table)
        if not self.tableExists(table.name):
            self.makeTable(table)
        else:
            self.justifyTable(table)

    def getQueryResults(self, query, params=None, firstTry = True, dictKeys=None):
        """perform the query and return the results as a list of tuples"""
        try:
            if self.printQuerys:
                print(query)
            cursor = self.conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            if dictKeys:
                rows = cursor.fetchall()
                retList = []
                if rows and len(rows[0]) != len(dictKeys):
                    raise ArchiveException(
                        "dictKeys.length.error",
                        "getQueryResults result row size does not match the size of provided dictKeys for query\n{}".format(query)
                    )
                for row in rows:
                    retList.append(dict(zip(dictKeys, row)))
                return retList
            return cursor.fetchall()
        except Exception as e:
            raise ArchiveException(*self.errorParams(query, e))
        finally:
            cursor.close()

    def performQuery(self, query, params=None, firstTry = True, returnId = False, commit = True):
        """ Perform query. Return True on success, false on failure"""
        try:
            if self.printQuerys:
                print(query)
            cursor = self.conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            if commit:
                self.conn.commit()
            if returnId:
                return cursor.lastrowid
            return True
        except Exception as e:
            raise ArchiveException(*self.errorParams(query, e))
        finally:
            cursor.close()

    def batchInsert(self, query, paramsList):
        """
        Similar to perform query, but doesn't commit until the end
        """
        for params in paramsList:
            self.performQuery(query, params, commit=False)
        self.conn.commit()
        return True

    def tableExists(self, name):
        """return True if the table exists, else false"""
        raise ArchiveException(*self.unimplemented("tableExists"))

    def makeTable(self, table):
        """Make a table from the given structure"""
        raise ArchiveException(*self.unimplemented("tableExists"))

    def justifyTable(self, table):
        """
        Check that database structure matches structure of given table.
        """
        raise ArchiveException(*self.unimplemented("tableExists"))


class SQLiteArchivist(Archivist):
    def __init__(self, filepath, logger=None):
        self.filepath = filepath
        super(SQLiteArchivist, self).__init__(logger)

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.filepath)
        except Exception as e:
            raise ArchiveException(*self.errorParams("connect", e))

    def tableExists(self, name):
        """return True if the table exists, else false"""

        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?;", (name,))

    def makeTable(self, table):
        """Make a table from the given structure"""
        columnDefs = []
        for column in table.columns:
            name = column['name']
            if name == table.primaryKey:
                if column["type"].lower() == "int":
                    d = '%s INTEGER PRIMARY KEY NOT NULL' % name
                else:
                    d = ' '.join([name, column["type"], 'PRIMARY KEY NOT NULL'])
            else:
                d = '%s %s' % (name, column['type'])
                if column['notNull']:
                    d = ' '.join([d,'NOT NULL'])
                if column['autoIncrement']:
                    d = ' '.join([d,'AUTOINCREMENT'])
                if column['default'] is not None:
                    if isinstance(column['default'], str):
                        column['default'] = "'%s'" % column['default']
                    d = ' '.join([d,'default %s' % column['default']])
            columnDefs.append(d)
        for indices in table.uniqueIndices:
            columnDefs.append(
                "CONSTRAINT {} UNIQUE ({})".format(
                    "_".join([table.name, *indices]),
                    ",".join(indices)
                )
            )
        for column, otherTable, otherColumn in table.foreignKeys:
            columnDefs.append(
                "FOREIGN KEY({}) REFERENCES {}({})".format(
                    column,
                    otherTable,
                    otherColumn
                )
            )
        query = 'CREATE TABLE %s(%s)' % (table.name,','.join(columnDefs))
        self.logger.info('Creating new table. Performing query: %s' % query)
        if not self.performQuery(query):
            return False
        return True

    def justifyTable(self, table):
        """
        Check that database structure matches structure of given table.
        Add columns if necessary.
        In switch to sqlite, disabled updating of primary keys.
        Fix that sometime.
        """
        query = 'PRAGMA table_info([%s]);' % table.name
        columns = {}
        columnNames = []
        for cols in self.getQueryResults(query):
            colId, name, columnType, notNull, default, isPrimaryKey = cols
            columnType = columnType.replace("auto_increment", "").strip()
            columns[name]  = Generic_class({'type': columnType, 'notNull': bool(notNull), 'isPrimaryKey':bool(isPrimaryKey), 'default': default})
            columnNames.append(name)
        for column in table.columns:
            # sqlite does not let you add a primary key after table creation
            if column['name'] not in columnNames:
                self.logger.warning('Missing columns found in table %s. Recreating table.' % (table.name, ))
                query = "DROP TABLE IF EXISTS %s" % table.name
                self.performQuery(query)
                self.makeTable(table)
                return True
            else:
                columnNames.remove(column['name'])
        if len(columnNames) > 0:
            self.logger.warning('Extra columns found in table %s. Recreating table.' % (table.name, ))
            query = "DROP TABLE IF EXISTS %s" % table.name
            self.performQuery(query)
            self.makeTable(table)
            return True


class PostgreArchivist(Archivist):
    timeFmt = "%Y-%m-%d %H:%M:%S"

    def __init__(self, dbname="dcrdata", host="localhost", user="dcrdata", password=None, port=5432, logger=None):
        assert password, "PostgreArchivist requires a password"
        self.dbname = dbname
        self.host = host
        self.user = user
        self.password = password
        super(PostgreArchivist, self).__init__(logger)

    def connect(self):
        try:
            self.conn = psycopg2.connect(dbname=self.dbname, user=self.user, host=self.host, password=self.password)
        except Exception as e:
            raise ArchiveException(*self.errorParams("\\connect", e))
    @staticmethod
    def timeStringToUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, PostgreArchivist.timeFmt))


class ArchiveException(Exception):
    """
    Custom exception to be thrown from Archivist
    """
    def __init__(self, name, message):
        self.name = name
        self.message = message
