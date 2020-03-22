"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

from decred.dcr import vsp
from decred.dcr.nets import testnet


VSP_URL = "https://dcrstakedinner.com"
API_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1Nzc0MzM0NDIsIm"
    "lzcyI6Imh0dHBzOi8vd3d3LmRjcnN0YWtlZGlubmVyLmNvbSIsImxvZ2dlZEluQ"
    "XMiOjQ2fQ.PEb000_TjQuBYxjRdh-VOaXMdV2GUw3_ZyIyp_tfpFE"
)
# Signing address is needed to validate server-reported redeem script.
SIGNING_ADDRESS = "TkKmVKG7u7PwhQaYr7wgMqBwHneJ2cN4e5YpMVUsWSopx81NFXEzK"


def test_vsp_live():
    the_vsp = vsp.VotingServiceProvider(VSP_URL, API_KEY, testnet.Name)
    the_vsp.authorize(SIGNING_ADDRESS)
    the_vsp.getStats()
    purc_info = the_vsp.getPurchaseInfo()
    # Test voting.
    if purc_info.voteBits & (1 << 1) != 0:
        nextVote = 1 | (1 << 2)
    else:
        nextVote = 1 | (1 << 1)
    the_vsp.setVoteBits(nextVote)
    purc_info = the_vsp.getPurchaseInfo()
    assert purc_info.voteBits == nextVote
