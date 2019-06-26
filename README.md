# TinyDecred

A Python 3 library for Decred. 

## Features

1. Pure-Python secp256k1 elliptical curve.

1. Serializable and de-serializable re-implementations of important go types
from the wire package, such as `MsgTx`, `BlockHeader`, `OutPoint`, etc. 

1. BIP-0044 keys. Account creation and management. PGP mnemonic seeds. 

1. Network parameter files for mainnet, testnet3, and simnet. 

1. Clients for the dcrdata block explorer API (websockets, pubsub, HTTP). 

1. Experimental PyQt5 light wallet. 

# Installation

Install by cloning the git repo. 
The `tinydecred` directory, or a symlink to the directory, will need to be in 
`PYTONPATH`. 

All dependencies are available through PyPi.

```
sudo pip3 install PyQt5==5.9.2 websocket_client blake256 base58 pynacl appdirs
```

though depending on your setup, you may or may not need `sudo`, and `pip3` might
be simply `pip`. 

You may have luck with newer versions of PyQt5, but `5.9.2` has been remarkably
stable.

# Application

TinyDecred is the name of the package, as well as the experimental light wallet
application. 
**The light wallet is experimental, and should not be used on mainnet.***

The programs runs as a system-tray application. 
The major difference is that "closing" the application instead minimizes it 
to the system tray, and reopening is through the system tray as well. 

To start the wallet, navigate to the `tinydecred` package directory, and run

```
python app.py --testnet
```




