# Contribution guidelines

Thank you for contributing to this project! The developers are part of the
[Decred community](https://decred.org/community/) and coordinate in a
[chat](https://chat.decred.org/#/room/#tinydecred:decred.org) on the
[Matrix](https://matrix.org/) platform, you'll need a (free) account to access
it.

## Bugs and new features

If you found a bug, before creating an issue please search among the
[open ones](https://github.com/decred/tinydecred/issues). Please add as many
useful details as you can.

If you'd like to request a new feature, either create an issue (again, after
searching first) or chat with us on Matrix (see above).

## Development

The [Poetry](https://python-poetry.org/) tool is used for dependency management
and packaging. You'll reformat your changes with the
[Black](https://black.readthedocs.io/) tool and run tests using
[pytest](https://www.pytest.org/).

Before each pull request is merged, a Github workflow action is run to make
sure that the changes meet some minimum requirements. The action definition
[file](./.github/workflows/python.yml) is a useful summary of the commands
you'll run while developing.

New tests should be written in the [pytest](https://docs.pytest.org/) format.
Existing tests in the stdlib `unittest` format may be rewritten to use pytest
as needed.

Tests may be debugged more conveniently using the
[PuDB](https://documen.tician.de/pudb/) console-based visual debugger, invoked
via the `./decred/dbg-pudb.sh` script.

For displaying line-by-line test coverage in a web browser see the
`./decred/coverage-html.sh` script.

## More information

Please find more information in the dcrd
[contribution guidelines](https://github.com/decred/dcrd/blob/master/docs/code_contribution_guidelines.md).
