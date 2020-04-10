"""
Copyright (c) 2020, The Decred developers
See LICENSE for details

This file implements Cython integration (see https://cython.org/) to generate
a C extension that speeds up the low-level secp256k1 crypto code. This is used
by the Poetry tool when generating the wheel archive via its `build` command.

It uses a currently undocumented Poetry feature, see:
https://github.com/python-poetry/poetry/issues/11#issuecomment-379484540

The shared library can also be built manually using the command:

$ cythonize -X language_level=3 -a -i ./decred/crypto/secp256k1/field.py
"""

# fmt: off
try:
    from Cython.Build import cythonize
except ImportError:
    def build(setup_kwargs):
        pass
else:
    def build(setup_kwargs):
        setup_kwargs.update(
            {"ext_modules": cythonize(["decred/crypto/secp256k1/field.py"])}
        )
# fmt: on
