# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Custom errors for the charm."""


class CharmConfigInvalidError(Exception):
    """Exception raised when a charm configuration is found to be invalid.

    Attrs:
        msg (str): Explanation of the error.
    """

    def __init__(self, msg: str):
        """Initialize a new instance of the CharmConfigInvalidError exception.

        Args:
            msg (str): Explanation of the error.
        """
        self.msg = msg


class SquidPathNotFoundError(Exception):
    """Exception raised when Squid path can't be found.

    Attrs:
        msg (str): Explanation of the error.
    """

    def __init__(self, msg: str):
        """Initialize a new instance of the SquidNotFoundError exception.

        Args:
            msg (str): Explanation of the error.
        """
        self.msg = msg
