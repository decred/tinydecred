"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

DcrdataClient.endpointList() for available enpoints.
"""

import json
from urllib.parse import urlencode
import urllib.request as urlrequest

from .helpers import formatTraceback


def get(url, **kwargs):
    return request(url, **kwargs)


def post(url, data, **kwargs):
    return request(url, data, **kwargs)


def request(
    url, postData=None, headers=None, urlEncode=False, supressErr=False, context=None
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
            req = urlrequest.Request(url, headers=headers, data=encoded)
        else:
            req = urlrequest.Request(url, headers=headers, method="GET")
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
                % (url, raw, formatTraceback(e)),
            )
    except Exception as e:
        raise Exception(
            "RequestError",
            "Error encountered in requesting path %s: %s" % (url, formatTraceback(e)),
        )
