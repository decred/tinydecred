"""
pyDcrData
DcrDataClient.endpointList() for available enpoints.
Arguments can be positional or keyword, not both.
"""
import urllib.request as urlrequest
import traceback
import json
import time
import calendar

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


class DcrDataClient:
    """
    DcrDataClient represents the base node. The only argument to the
    constructor is the path to a DCRData server, e.g. http://explorer.dcrdata.org.
    """
    timeFmt = "%Y-%m-%d %H:%M:%S"

    def __init__(self, baseUri):
        """
        Build the DcrDataPath tree. 
        """
        self.baseUri = baseUri.rstrip('/').rstrip("/api") + "/api"
        root = self.root = DcrDataPath()
        self.listEntries = []
        # /list returns a json list of enpoints with parameters in template format, base/A/{param}/B
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
    @staticmethod
    def RFC3339toUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, "%Y-%m-%dT%H:%M:%SZ"))


class DcrDataException(Exception):
    def __init__(self, name, message):
        self.name = name
        self.message = message
