"""
Copyright (c) 2020, The Decred developers
See LICENSE for details
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
