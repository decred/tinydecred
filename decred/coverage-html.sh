#!/bin/sh
## To generate line-by-line test coverage viewable in a web browser,
## change to this directory, then install the dependencies:
# poetry install
## The coverage report will be in the ./htmlcov/ directory.
poetry run pytest --cov-report=html --cov=decred ./tests/
