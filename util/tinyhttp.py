"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

DcrdataClient.endpointList() for available enpoints.
"""
import json
from urllib.parse import urlencode
import urllib.request as urlrequest
from tinydecred.util.helpers import formatTraceback


def get(uri, **kwargs):
    return request(uri, **kwargs)


def post(uri, data, **kwargs):
    return request(uri, data, **kwargs)


def request(
    uri, postData=None, headers=None, urlEncode=False, supressErr=False, context=None
):
    try:
        headers = headers if headers else {}
        if postData:
            if urlEncode:
                # encode the data in url query string form, without ?.
                encoded = urlencode(postData).encode("utf-8")
            else:
                # encode the data as json.
                encoded = json.dumps(postData).encode("utf-8")
            req = urlrequest.Request(uri, headers=headers, data=encoded)
        else:
            req = urlrequest.Request(uri, headers=headers, method="GET")
        raw = urlrequest.urlopen(req, context=context).read().decode()
        try:
            # try to decode the response as json, but fall back to just
            # returning the string.
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
        except Exception as e:
            raise Exception(
                "JSONError",
                "Failed to decode server response from path %s: %s : %s"
                % (uri, raw, formatTraceback(e)),
            )
    except Exception as e:
        raise Exception(
            "RequestError",
            "Error encountered in requesting path %s: %s" % (uri, formatTraceback(e)),
        )
