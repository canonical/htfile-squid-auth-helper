#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more at: https://juju.is/docs/sdk

"""A subordinate charm enabling support for digest authentication on Squid Reverseproxy charm."""

import json
from pathlib import Path

import ops
import passlib.apache
from passlib import pwd
from tabulate import tabulate

AUTH_HELPER_RELATION_NAME = "squid-auth-helper"

DIGEST_FILEPATH = Path("/etc/squid3/password-file")
DIGEST_REALM = "digest"

EVENT_FAIL_RELATION_MISSING_MESSAGE = "Integrate the charm to a Squid Reverseproxy charm before."
STATUS_BLOCKED_RELATION_MISSING_MESSAGE = (
    "Waiting for integration with Squid Reverseproxy charm..."
)


class DigestSquidAuthHelperCharm(ops.CharmBase):
    """A subordinate charm enabling support for digest auth on Squid Reverseproxy charm."""

    def __init__(self, *args):
        """Construct the charm.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)

        self.digest = passlib.apache.HtdigestFile(default_realm=DIGEST_REALM)

        self.framework.observe(self.on.start, self._on_start)

        self.framework.observe(
            self.on[AUTH_HELPER_RELATION_NAME].relation_created,
            self._on_squid_auth_helper_relation_created,
        )
        self.framework.observe(
            self.on[AUTH_HELPER_RELATION_NAME].relation_broken,
            self._on_squid_auth_helper_relation_broken,
        )

        self.framework.observe(self.on.create_user_action, self._on_create_user)
        self.framework.observe(self.on.remove_user_action, self._on_remove_user)
        self.framework.observe(self.on.list_users_action, self._on_list_users)

    def _on_squid_auth_helper_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        """Handle the relation created event for squid-auth-helper relation of the charm.

        Store in the relation databag the configuration parameters for the squid proxy.

        Args:
            event: Event for the squid-auth-helper relation created.
        """
        self._create_and_save_digest_file()
        relation_data = [
            {
                "scheme": "digest",
                "program": f"/usr/lib/squid3/digest_pw_auth -c {DIGEST_FILEPATH}",
                "children": 5,
            }
        ]

        event.relation.data[self.app]["auth-params"] = json.dumps(relation_data)
        self.unit.status = ops.ActiveStatus()

    def _on_squid_auth_helper_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle the relation broken event for squid-auth-helper relation of the charm."""
        self.unit.status = self._block_if_not_related_to_squid()

    def _on_start(self, _: ops.StartEvent) -> None:
        """Handle the start of the charm."""
        self.unit.status = self._block_if_not_related_to_squid()

    def _on_create_user(self, event: ops.ActionEvent) -> None:
        """Handle the create user action.

        This action allows to create a user that can be used in Squid proxy ACLs.

        Args:
            event: Event for the create user action
        """
        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        username = event.params["username"]
        if self.digest.get_hash(username):
            event.fail(f"User {username} already exists.")
            return

        generated_password = pwd.genword()
        if self.digest.set_password(username, generated_password):
            event.fail("An error occurred when saving the htdigest file.")
            return

        self._create_and_save_digest_file()
        results = {"username": username, "password": generated_password, "realm": DIGEST_REALM}
        event.set_results(results)

    def _on_remove_user(self, event: ops.ActionEvent) -> None:
        """Handle the remove user action.

        This action allows to remove a user that can be used in Squid proxy ACLs.
        This action fails if the user doesn't exists.

        Args:
            event: Event for the remove user action
        """
        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        username = event.params["username"]
        if not self.digest.delete(username):
            event.fail(f"User {username} doesn't exists.")
            return

        self._create_and_save_digest_file()
        event.set_results({"success": True})

    def _on_list_users(self, event: ops.ActionEvent) -> None:
        """Handle the list users action.

        List the users available in the Squid proxy ACLs.

        Args:
            event: Event for the list users action
        """
        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        user_list = {user: self.digest.get_hash(user) for user in self.digest.users()}
        headers = ["Username", "Hash password"]
        event.set_results(
            {
                "formatted": tabulate(user_list.items(), headers=headers, tablefmt="grid"),
                "list": user_list,
            }
        )

    def _block_if_not_related_to_squid(self) -> ops.StatusBase:
        """Set the charm to BlockedStatus if no squid-auth-helper relation exists.

        Returns: A blocked status if no relation exists, an active status otherwise
        """
        relations = self.model.relations[AUTH_HELPER_RELATION_NAME]
        if not relations:
            return ops.BlockedStatus(STATUS_BLOCKED_RELATION_MISSING_MESSAGE)
        return ops.ActiveStatus()

    def _create_and_save_digest_file(self) -> None:
        """Create the htdigest file and saves it."""
        DIGEST_FILEPATH.parent.mkdir(parents=True, exist_ok=True)
        DIGEST_FILEPATH.touch(exist_ok=True)

        self.digest.save(DIGEST_FILEPATH)


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(DigestSquidAuthHelperCharm)
