#!/bin/sh
# Debug tests using the interactive pudb debugger.
poetry run pytest --pdbcls=pudb.debugger:Debugger --trace "$1"
