#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more at: https://juju.is/docs/sdk

"""A subordinate charm enabling support for digest authentication on Squid Reverseproxy charm."""

import logging

import ops

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

AUTH_HELPER_RELATION_NAME = "squid-auth-helper"


class DigestSquidAuthHelperCharm(ops.CharmBase):
    """A subordinate charm enabling support for digest authentication on Squid Reverseproxy charm."""

    def __init__(self, *args):
        """Construct the charm

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self.framework.observe(self.on[AUTH_HELPER_RELATION_NAME].relation_joined, self._on_squid_auth_helper_relation_joined)


    def _on_httpbin_pebble_ready(self, event: ops.PebbleReadyEvent):



if __name__ == "__main__":  # pragma: nocover
    ops.main.main(DigestSquidAuthHelperCharm)
