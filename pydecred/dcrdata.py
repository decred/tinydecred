"""
pyDcrData
DcrDataClient.endpointList() for available enpoints.
Arguments can be positional or keyword, not both.
"""
import urllib.request as urlrequest
from urllib.parse import urlencode
import traceback
from tinydecred.pydecred import dcrjson
import time
import calendar
import unittest

VERSION = "0.0.1"
HEADERS = {"User-Agent": "PyDcrData/%s" % VERSION}


def getUri(uri):
    return performRequest(uri)

def postData(uri, data):
    return performRequest(uri, data)

def performRequest(uri, post=None):
    try:
        headers = HEADERS
        if post:
            encoded = dcrjson.dump(post).encode("utf-8")
            print("--encoded: %r" % encoded)
            req = urlrequest.Request(uri, data=encoded)
            req.add_header("User-Agent", "PyDcrData/%s" % VERSION)
            req.add_header("Content-Type", "application/json; charset=utf-8")
        else:
            req = req = urlrequest.Request(uri, headers=headers, method="POST" if post else "GET", data=post)
        raw = urlrequest.urlopen(req).read().decode()
        try:
            return dcrjson.load(raw)
        except dcrjson.JSONDecodeError:
            # A couple of paths return simple strings or integers. block/best/hash or block/best/height for instance.
            return raw
        except Exception as e:
            raise DcrDataException("JSONError", "Failed to decode server response from path %s: %s : %s : %s" % (uri, raw, repr(e), traceback.print_tb(e.__traceback__)))
    except Exception as e:
        raise DcrDataException("RequestError", "Error encountered in requesting path %s: %s : %s" % (uri, repr(e), traceback.print_tb(e.__traceback__)))


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
        Keeps a list of arguments associated with path templates to differentiate.
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
        raise DcrDataException("ArgumentError", "Supplied arguments, %r, do not match any of the know call signatures, %r." % 
            (args if args else kwargs, [argList for argList, _ in self.callSigns]))

    def __getattr__(self, key):
        if key in self.subpaths:
            return self.subpaths[key]
        raise DcrDataException("SubpathError", "No subpath %s found in datapath" % (key,))

    def __call__(self, *args, **kwargs):
        return getUri(self.getCallsignPath(*args, **kwargs))

    def post(self, data):
        return postData(self.getCallsignPath(), data)


class DcrDataClient:
    """
    DcrDataClient represents the base node. The only argument to the
    constructor is the path to a DCRData server, e.g. http://explorer.dcrdata.org.
    """
    timeFmt = "%Y-%m-%d %H:%M:%S"

    def __init__(self, baseUri, customPaths=None):
        """
        Build the DcrDataPath tree. 
        """
        self.baseUri = baseUri.rstrip('/').rstrip("/api")
        self.baseApi = self.baseUri + "/api"
        root = self.root = DcrDataPath()
        self.listEntries = []
        customPaths = customPaths if customPaths else []
        # /list returns a json list of enpoints with parameters in template format, base/A/{param}/B
        endpoints = getUri(self.baseApi + "/list")
        endpoints += customPaths

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
            baseUri = self.baseUri if "insight" in path else self.baseApi
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
    @staticmethod
    def RFC3339toUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, "%Y-%m-%dT%H:%M:%SZ"))


class DcrDataException(Exception):
    def __init__(self, name, message):
        self.name = name
        self.message = message

class TestDcrData(unittest.TestCase):
    def test_post(self):
        dcrdata = DcrDataClient("http://localhost:7777", customPaths={
            "/tx/send",
            "/insight/api/addr/{address}/utxo",
            "insight/api/tx/send"
        })

        tx = "01000000010f6d7f5d37408065b3646360a4c40d03a6e2cfbeb285cd800e0eba6e324a0d900200000000ffffffff0200e1f5050000000000001976a9149905a4df9d118e0e495d2bb2548f1f72bc1f305888ac1ec12df60600000000001976a91449c533219ff4eb65603ab31d827c9a22b72b429488ac00000000000000000100ac23fc0600000000000000ffffffff6b483045022100b602bfb324a24801d914ec2f6a48ee27d65e2cde3fa1e71877fda23d7bae4a1f02201210c789dc33fe156bd086c3779af1953e937b24b0bba4a8adb9532b4eda53c00121035fc391f92ba86e8d5b893d832ced31e6a9cc7a9c1cddc19a29fa53dc1fa2ff9f"
        r = dcrdata.insight.api.tx.send.post({
            "rawtx": tx,
        })
        print(repr(r))