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
    The "get" responses will use "url" as a key, while the "post" responses
    will use "(url, repr(data))".
    """
    q = {}

    def mock_get(url, **kwargs):
        return q[url].pop()

    def mock_post(url, data, **kwargs):
        return q[(url, repr(data))].pop()

    monkeypatch.setattr(tinyhttp, "get", mock_get)
    monkeypatch.setattr(tinyhttp, "post", mock_post)

    def queue(k, v):
        q.setdefault(k, []).append(v)

    return queue
