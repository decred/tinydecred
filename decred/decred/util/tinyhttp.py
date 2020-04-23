"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details

See DcrdataClient.endpointList() for available enpoints.
"""

import json
from ssl import SSLContext
from typing import Dict, List, Optional, Union
from urllib.parse import urlencode
import urllib.request as urlrequest

from decred import DecredError

from .helpers import formatTraceback


def get(url: str, **kwargs) -> Union[Dict[str, str], List[int], str]:
    """
    A convenience function to make a GET HTTP request.

    Args:
        url: The URL to connect to.
        kwargs: Other arguments to pass to the request function.
    """
    return request(url, **kwargs)


def post(
    url: str, data: Dict[str, str], **kwargs
) -> Union[Dict[str, str], List[int], str]:
    """
    A convenience function to make a POST HTTP request.

    Args:
        url: The URL to connect to.
        data: The data to send.
        kwargs: Other arguments to pass to the request function.
    """
    return request(url, data, **kwargs)


def request(
    url: str,
    postData: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    urlEncode: Optional[bool] = False,
    context: Optional[SSLContext] = None,
) -> Union[Dict[str, str], List[int], str]:
    """
    Make an HTTP request and try to decode the payload as JSON. If an error
    happens while decoding, return the raw payload.

    If any postData is passed, the POST method is used, otherwise the GET one.

    Args:
        url: The URL to connect to.
        postData: The data to POST, if any.
        headers: Any custom headers to add to the request.
        urlEncode: Whether to urlencode the postData.
        context: An SSLContext used to encrypt the request.

    Returns:
        The decoded JSON data or the raw payload.
    """
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
