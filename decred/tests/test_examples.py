"""
Copyright (c) 2019, The Decred developers
"""

import importlib.util
import os
from pathlib import Path
import py_compile


def test_compile():
    exampleDir = Path(__file__).resolve().parent.parent / "examples"

    for filename in os.listdir(exampleDir):
        # The "plot_ticket_price.py" file imports matplotlib, which is not a TD
        # dependency, so skip that file.
        if not filename.endswith(".py") or "plot_" in filename:
            continue
        path = Path(exampleDir) / filename
        assert py_compile.compile(path) is not None
        spec = importlib.util.spec_from_file_location(filename.split(".")[0], path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
