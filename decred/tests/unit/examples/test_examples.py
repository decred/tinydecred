"""
Copyright (c) 2019, The Decred developers
"""

import importlib.util
import os
from pathlib import Path
import py_compile
from tempfile import TemporaryDirectory

import decred


def test_compile():
    exampleDir = Path(os.path.realpath(decred.__file__)).parent.parent / "examples"

    with TemporaryDirectory() as tempDir:
        for filename in os.listdir(exampleDir):
            # The "plot_ticket_price.py" file imports matplotlib, which is not a TD
            # dependency, so skip that file.
            if not filename.endswith(".py") or "plot_" in filename:
                continue
            path = os.path.join(exampleDir, filename)
            cfile = os.path.join(tempDir, filename + ".pyc")
            assert py_compile.compile(path, cfile=cfile) is not None
            spec = importlib.util.spec_from_file_location(filename.split(".")[0], path)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
