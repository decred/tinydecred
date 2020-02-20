"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import pytest

from decred.util import tinyhttp


@pytest.fixture
def http_get_post(monkeypatch):
    """
    Tests will use the returned "queue" function to add responses they want
    returned from both tinyhttp "get" and "post" functions.
    The "get" responses will use "uri" as a key, while the "post" responses
    will use "(uri, repr(data))".
    """
    q = {}

    def mock_get(uri, **kwargs):
        return q[uri].pop()

    def mock_post(uri, data, **kwargs):
        return q[(uri, repr(data))].pop()

    monkeypatch.setattr(tinyhttp, "get", mock_get)
    monkeypatch.setattr(tinyhttp, "post", mock_post)

    def queue(k, v):
        q.setdefault(k, []).append(v)

    return queue
