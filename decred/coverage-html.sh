#!/bin/sh
## Change to this directory, then install the dependencies:
# poetry install
## The coverage report will be in the ./htmlcov/ directory.
poetry run pytest --cov-config=.coveragerc --cov-report=html --cov=decred ./tests/
