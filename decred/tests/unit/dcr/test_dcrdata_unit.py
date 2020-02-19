"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import pytest

from decred.dcr import dcrdata


def test_dcrdatapath(http_post):
    ddp = dcrdata.DcrdataPath()

    # __getattr__
    with pytest.raises(dcrdata.DcrDataException):
        ddp.no_such_path()

    # Empty URI, needed for post.
    with pytest.raises(dcrdata.DcrDataException):
        ddp.getCallsignPath()
    ddp.addCallsign([], "")
    csp = ddp.getCallsignPath()
    assert csp == ""

    # Non-empty URI.
    with pytest.raises(dcrdata.DcrDataException):
        ddp.getCallsignPath("address")
    ddp.addCallsign(["address"], "/%s")
    csp = ddp.getCallsignPath("address", address="1234")
    assert csp == "/address?address=1234"

    # Post.
    ret = ddp.post("")
    assert ret == {}


# Keys are "(uri, repr(data))", see conftest.py .
test_dcrdatapath.HTTP_POST_RESP = {
    ("", "''"): {},
}
