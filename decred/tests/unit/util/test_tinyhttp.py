"""
Copyright (c) 2020, the Decred developers
See LICENSE for details
"""

import urllib.request as urlrequest

import pytest

from decred import DecredError
from decred.util import tinyhttp


@pytest.fixture
def urlopen(monkeypatch):
    """
    Tests will use the returned "queue" function to add responses they want
    returned from "urllib.request.urlopen" when used in tinyhttp.
    """
    q = {}

    def mock_urlopen(req, context=None):
        """
        Args:
            req: an object with "full_url" and "data" attributes, for instance
                urllib.request.Request.
        Return:
            an object with "read" and "decode" methods, for instance
                http.client.HTTPResponse.
        """

        class Response(str):
            read = lambda self: self
            decode = lambda self: self

        key = (req.full_url, req.data)
        print(req.data)
        reply = q[key].pop()
        return Response(reply)

    monkeypatch.setattr(urlrequest, "urlopen", mock_urlopen)

    def queue(url, data=None, reply=""):
        q.setdefault((url, data), []).append(reply)

    return queue


def test_get(urlopen):
    urlopen("http://example.org/", None, "[0, 1, 2]")
    assert tinyhttp.get("http://example.org/") == [0, 1, 2]


def test_post(urlopen):
    urlopen("http://example.org/", b'{"a": "b"}', '{"c": "d"}')
    assert tinyhttp.post("http://example.org/", {"a": "b"}) == {"c": "d"}


def test_request_urlencoded(urlopen):
    urlopen("http://example.org/", b"a=b", '{"c": "d"}')
    assert tinyhttp.request(
        "http://example.org/", postData={"a": "b"}, urlEncode=True,
    ) == {"c": "d"}


def test_request_urlopen_error(monkeypatch):
    def urlopen_error(req, context=None):
        raise DecredError("test error")

    monkeypatch.setattr(urlrequest, "urlopen", urlopen_error)
    with pytest.raises(DecredError):
        tinyhttp.get("http://example.org/")


def test_request_json_decode_error(urlopen):
    urlopen("http://example.org/", b'{"a": "b"}', "nojson")
    assert tinyhttp.request("http://example.org/", postData={"a": "b"}) == "nojson"
