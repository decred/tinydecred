"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import pytest

from decred.util import tinyhttp


@pytest.fixture
def http_get(request, monkeypatch):
    """
    Use this fixture in tests while defining the responses to be returned in
    a "HTTP_GET_RESP" function-level dict with "uri" as keys.
    """
    get_resp = getattr(request.function, "HTTP_GET_RESP")

    def mock_get(uri, **kwargs):
        nonlocal get_resp
        return get_resp[uri]

    # Avoid calling the actual tinyhttp.get .
    monkeypatch.setattr(tinyhttp, "get", mock_get)


@pytest.fixture
def http_post(request, monkeypatch):
    """
    Use this fixture in tests while defining the responses to be returned in
    a "HTTP_POST_RESP" function-level dict with "(uri, repr(data))" as keys.
    """
    post_resp = getattr(request.function, "HTTP_POST_RESP")

    def mock_post(uri, data, **kwargs):
        nonlocal post_resp
        return post_resp[(uri, repr(data))]

    # Avoid calling the actual tinyhttp.post .
    monkeypatch.setattr(tinyhttp, "post", mock_post)
