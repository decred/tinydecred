## Examples

#### Create a wallet

```
from tinydecred.wallet import Wallet
from tinydecred.pydecred import testnet

# Create an encrypted, password-protected wallet file.
password = "mypassword"
walletPath = "testnet_wallet.db"
mnemonicSeed, wallet = Wallet.create(walletPath, password, testnet)

# print the seed words and an address
print("mnemonic seed:\n%s" % " ".join(mnemonicSeed))
print("address: %s" % wallet.paymentAddress())
```

Send some DCR to your new testnet address from 
[a faucet](https://faucet.decred.org/requestfaucet) to get some funds before the
next step.

#### Send some DCR

```
from tinydecred.wallet import Wallet
from tinydecred.pydecred import testnet
from tinydecred.pydecred.dcrdata import DcrdataBlockchain

# We need a class that implements the Signals API
class Signals(object):
	def balance(self, bal):
		print(bal)

# DcrdataBlockchain implements a Blockchain API (see api.py) for Decred.
dbPath = "dcr_testnet.db"
dcrdata = "https://testnet.dcrdata.org"
blockchain = DcrdataBlockchain(dbPath, testnet, dcrdata)

# Create the wallet from file.
password = "mypassword"
walletPath = "testnet_wallet.db"
wallet = Wallet.openFile(walletPath, password)

# Open the wallet and send some DCR.
recipient = "TsfDLrRkk9ciUuwfp2b8PawwnukYD7yAjGd" # testnet return address
value = int(1 * 1e8) # 1 DCR, atom units
acct = 0 # Every wallet has a zeroth Decred account
with wallet.open(acct, password, blockchain, Signals()):
	wallet.sync()
	tx = wallet.sendToAddress(value, recipient)
	print("transaction ID: %s" % tx.id())

blockchain.close()
```

#### Plotting

To run this example, you will need the matplotlib package 
(`pip install matplotlib`).

```
from tinydecred.pydecred.dcrdata import DcrdataClient
from matplotlib import pyplot as plt

dcrdata = DcrdataClient("https://explorer.dcrdata.org")
ticketPrice = dcrdata.chart("ticket-price")
# "x" is UNIX timestamp, "y" is ticket price, in atoms
plt.plot(ticketPrice["x"], [atoms*1e-8 for atoms in ticketPrice["y"]])
plt.show()
```

