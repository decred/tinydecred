"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""


class DecredError(Exception):
    pass


def unblob_check(class_name, version, pushes, check_data):
    """
    Check version and pushes to unblob.

    Args:
        class_name str: the class name that will appear in error messages.
        version int: the version number that will be checked.
        pushes int: the number of pushes that will be checked.
        check_data dict: keys are version numbers, values are number of
            expected pushes.

    Raises:
        NotImplementedError if version is not in check_data keys.
        DecredError if pushes is not the value in check_data keyed by version.
    """
    if version not in check_data.keys():
        raise NotImplementedError(f"{class_name}: unsupported version {version}")
    expected_pushes = check_data[version]
    if pushes != expected_pushes:
        raise DecredError(
            f"{class_name}: expected {expected_pushes} pushes, got {pushes}"
        )
