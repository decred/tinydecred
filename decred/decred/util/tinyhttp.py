"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

DcrdataClient.endpointList() for available enpoints.
"""

import json
from urllib.parse import urlencode
import urllib.request as urlrequest

from decred import DecredError

from .helpers import formatTraceback


def get(url, **kwargs):
    return request(url, **kwargs)


def post(url, data, **kwargs):
    return request(url, data, **kwargs)


def request(url, postData=None, headers=None, urlEncode=False, context=None):
    # GET method used when encoded data is None.
    encoded = None
    if postData:
        if urlEncode:
            # Encode the data in URL query string form.
            encoded = urlencode(postData).encode("utf-8")
        else:
            # Encode the data as JSON.
            encoded = json.dumps(postData).encode("utf-8")

    headers = headers if headers else {}
    req = urlrequest.Request(url, headers=headers, data=encoded)

    try:
        raw = urlrequest.urlopen(req, context=context).read().decode()
    except Exception as err:
        raise DecredError(f"Error in requesting URL {url}: {formatTraceback(err)}")

    try:
        # Try to decode the response as JSON, but fall back to just
        # returning the string.
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw
