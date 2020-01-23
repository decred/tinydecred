# tinydecred

[![Build Status](https://github.com/decred/tinydecred/workflows/Build%20and%20Test/badge.svg)](https://github.com/decred/tinydecred/actions)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](https://copyfree.org/)

TinyDecred is a Python 3 toolkit that can be used to integrate
[Decred](https://decred.org/) into Python projects.

The [`decred`](./decred) package contains everything needed to create wallets
to send and receive DCR.

The [`tinywallet`](./tinywallet) package contains a wallet based on the
`decred` toolkit.

Each package may be installed from the [Python Package Index](https://pypi.org/)
using the [`pip`](https://pip.pypa.io/) command as usual.

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
