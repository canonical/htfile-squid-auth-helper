#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more at: https://juju.is/docs/sdk

"""A subordinate charm enabling support for digest authentication on Squid Reverseproxy charm."""

import json

import ops
from passlib import pwd
from tabulate import tabulate

from charm_state import AuthenticationTypeEnum
from charm_state import inject as inject_charm_state

AUTH_HELPER_RELATION_NAME = "squid-auth-helper"

EVENT_FAIL_RELATION_MISSING_MESSAGE = "Integrate the charm to a Squid Reverseproxy charm before."
STATUS_BLOCKED_RELATION_MISSING_MESSAGE = (
    "Waiting for integration with Squid Reverseproxy charm..."
)


class HtfileSquidAuthHelperCharm(ops.CharmBase):
    """A subordinate charm enabling support for basic or digest auth on Squid Reverseproxy."""

    def __init__(self, *args):
        """Construct the charm.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)

        self._charm_state = None

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

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

    @inject_charm_state
    def _on_squid_auth_helper_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        """Handle the relation created event for squid-auth-helper relation of the charm.

        Store in the relation databag the configuration parameters for the squid proxy.

        Args:
            event: Event for the squid-auth-helper relation created.
        """
        event.relation.data[self.unit]["auth-params"] = json.dumps(
            self._charm_state.get_as_relation_data()
        )
        self.unit.status = ops.ActiveStatus()

    def _on_squid_auth_helper_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle the relation broken event for squid-auth-helper relation of the charm."""
        # Todo: Remove vault file
        self.unit.status = self._block_if_not_related_to_squid()

    @inject_charm_state
    def _on_install(self, _: ops.StartEvent) -> None:
        """Handle the start of the charm."""
        vault_filepath = self._charm_state.squid_auth_config.vault_filepath
        vault_filepath.parent.mkdir(parents=True, exist_ok=True)
        vault_filepath.parent.chmod(0o755)
        vault_filepath.touch(0o644, exist_ok=True)

        self.unit.status = self._block_if_not_related_to_squid()

    @inject_charm_state
    def _on_config_changed(self, _: ops.ConfigChangedEvent) -> None:
        """Handle configuration changes made by user."""
        relations = self.model.relations[AUTH_HELPER_RELATION_NAME]

        if not relations:
            self.unit.status = ops.BlockedStatus(STATUS_BLOCKED_RELATION_MISSING_MESSAGE)
            return

        # Todo: Remove vault file if authentication_type changed
        for relation in relations:
            relation.data[self.unit]["auth-params"] = json.dumps(
                self._charm_state.get_as_relation_data()
            )
        self.unit.status = ops.ActiveStatus()

    @inject_charm_state
    def _on_create_user(self, event: ops.ActionEvent) -> None:
        """Handle the create user action.

        This action allows to create a user that can be used in Squid proxy ACLs.

        Args:
            event: Event for the create user action.
        """
        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        vault = self._charm_state.get_auth_vault()

        username = event.params["username"]
        if vault.get_hash(username):
            event.fail(f"User {username} already exists.")
            return

        generated_password = pwd.genword()
        if vault.set_password(username, generated_password):
            event.fail("An error occurred when saving the vault file.")
            return

        vault.save()
        results = {
            "username": username,
            "password": generated_password,
        }

        if (
            self._charm_state.squid_auth_config.authentication_type
            == AuthenticationTypeEnum.DIGEST
        ):
            results.update(
                {
                    "realm": self._charm_state.squid_auth_config.realm,
                }
            )

        event.set_results(results)

    @inject_charm_state
    def _on_remove_user(self, event: ops.ActionEvent) -> None:
        """Handle the remove user action.

        This action allows to remove a user that can be used in Squid proxy ACLs.
        This action fails if the user doesn't exists.

        Args:
            event: Event for the remove user action.
        """
        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        vault = self._charm_state.get_auth_vault()

        username = event.params["username"]
        if not vault.delete(username):
            event.fail(f"User {username} doesn't exists.")
            return

        vault.save()
        event.set_results({"success": True})

    @inject_charm_state
    def _on_list_users(self, event: ops.ActionEvent) -> None:
        """Handle the list users action.

        List the users available in the Squid proxy ACLs.

        Args:
            event: Event for the list users action.
        """
        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        vault = self._charm_state.get_auth_vault()

        user_list = {user: vault.get_hash(user) for user in vault.users()}
        headers = ["Username", "Hash password"]
        event.set_results(
            {
                "formatted": tabulate(user_list.items(), headers=headers, tablefmt="grid"),
                "list": str(user_list),
            }
        )

    def _block_if_not_related_to_squid(self) -> ops.StatusBase:
        """Set the charm to BlockedStatus if no squid-auth-helper relation exists.

        Returns: A blocked status if no relation exists, an active status otherwise.
        """
        relations = self.model.relations[AUTH_HELPER_RELATION_NAME]
        if not relations:
            return ops.BlockedStatus(STATUS_BLOCKED_RELATION_MISSING_MESSAGE)
        return ops.ActiveStatus()


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(HtfileSquidAuthHelperCharm)
