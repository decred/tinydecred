"""
Copyright (c) 2019, The Decred developers

This example script will pull ticket price data from dcrdata and plot using 
matplotlib. The matplotlib package is not a tinydecred dependency, so it should
be installed separately with `pip3 install matplotlib`.
"""
from tinydecred.pydecred.dcrdata import DcrdataClient
from tinydecred.util.helpers import mktime
try:
	from matplotlib import pyplot as plt
except ImportError:
	print("matplotlib import error. Did you 'pip3 install matplotlib'?")
	exit()

# Create a dcrdata client and grab the ticket price data.
dcrdata = DcrdataClient("https://dcrdata.decred.org")
ticketPrice = dcrdata.chart("ticket-price")
# ticketPrice["x"] is UNIX timestamp
# ticketPrice["y"] is ticket price, in atoms
# these keys will change. see https://github.com/decred/dcrdata/pull/1507

# Make the axes pretty.
ax = plt.gca() # gca = get current axes
years = range(2016, 2026)
ax.set_xticks([mktime(year) for year in years])
ax.set_xticklabels([str(year) for year in years])
ax.set_xlabel("date")
ax.set_ylabel("ticket price (DCR)")

ax.plot(ticketPrice["x"], [atoms*1e-8 for atoms in ticketPrice["y"]], 
	color="#222222")
plt.show()
