"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import pytest

from decred.dcr import dcrdata


def test_dcrdatapath(http_get_post):
    ddp = dcrdata.DcrdataPath()

    # __getattr__
    with pytest.raises(dcrdata.DcrDataError):
        ddp.no_such_path()

    # Empty URI, needed for post.
    with pytest.raises(dcrdata.DcrDataError):
        ddp.getCallsignPath()
    ddp.addCallsign([], "")
    csp = ddp.getCallsignPath()
    assert csp == ""

    # Non-empty URI.
    with pytest.raises(dcrdata.DcrDataError):
        ddp.getCallsignPath("address")
    ddp.addCallsign(["address"], "/%s")
    csp = ddp.getCallsignPath("address", address="1234")
    assert csp == "/address?address=1234"

    # Post. Queue the response we want first.
    http_get_post(("", "'data'"), {})
    ret = ddp.post("data")
    assert ret == {}
