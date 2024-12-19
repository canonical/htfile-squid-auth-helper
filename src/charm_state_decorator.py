# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""This module defines utility functions to use by the Charm."""
import logging
import typing
from functools import wraps

import ops

from exceptions import CharmConfigInvalidError

logger = logging.getLogger(__name__)

C = typing.TypeVar("C", bound=ops.CharmBase)
E = typing.TypeVar("E", bound=ops.EventBase)


def block_if_invalid_config(
    method: typing.Callable[[C, E], None]
) -> typing.Callable[[C, E], None]:
    """Create a decorator that puts the charm in blocked state if the config is wrong.

    Args:
        method: observer method to wrap.

    Returns:
        the function wrapper
    """

    @wraps(method)
    def wrapper(instance: C, event: E) -> None:
        """Block the charm if the config is wrong.

        Args:
            instance: the instance of the class with the hook method.
            event: the event for the observer

        Returns:
            The value returned from the original function. That is, None.
        """
        try:
            return method(instance, event)
        except CharmConfigInvalidError as exc:
            logger.exception("Wrong Charm Configuration")
            status = ops.BlockedStatus(exc.msg)
            instance.unit.status = status
            if instance.unit.is_leader():
                instance.app.status = status
            return None

    return wrapper
