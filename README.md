# tinydecred

TinyDecred is a Python 3 toolkit that can be used to integrate
[Decred](https://decred.org/) into Python projects.

The [`decred`](./decred) package contains everything needed to create wallets
to send and receive DCR.

The [`tinywallet`](./tinywallet) package contains a wallet based on the
`decred` toolkit.

Each package may be installed from the [Python Package Index](https://pypi.org/)
using the [`pip`](https://pip.pypa.io/) command as usual.

## Requirements

To run tinydecred on your machine you will need to set up the following. 

- pip install websocket_client
- pip install blake256
- pip install base58
- pip install PyNaCl
- pip install appdirs

Set up and run dcrd. Ensure your rpcusername and rpcpassword is set in your dcrd config file.
Installation guide can be found [`here`](https://docs.decred.org/wallets/cli/dcrd-setup/).

## Status

[![Check and test both packages](https://github.com/decred/tinydecred/workflows/Check%20and%20test%20both%20packages/badge.svg)](https://github.com/decred/tinydecred/actions)
[![Test coverage](https://img.shields.io/badge/coverage-98%25-green)](./decred/coverage-html.sh)

### PyPI

[![PyPI release](https://img.shields.io/pypi/v/decred)](https://pypi.org/project/decred/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/decred)](https://docs.python.org/3/)

### GitHub

[![GitHub commit activity](https://img.shields.io/github/commit-activity/y/decred/tinydecred)](https://github.com/decred/tinydecred/graphs/commit-activity)
[![GitHub contributors](https://img.shields.io/github/contributors/decred/tinydecred)](https://github.com/decred/tinydecred/graphs/contributors)
[![GitHub](https://img.shields.io/github/license/decred/tinydecred)](./LICENSE)


## Roadmap

In no particular order:

- Staking
- Schnorr signatures and Edwards curve
- SPV Node
- Bitcoin accounts
- Decred DEX integration
- Lightning network

## Contributing

See the [contribution guidelines](./CONTRIBUTING.md).
