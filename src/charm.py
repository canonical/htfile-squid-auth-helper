#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more at: https://juju.is/docs/sdk

"""A subordinate charm enabling support for digest authentication on Squid Reverseproxy charm."""

import json
from typing import Any

import ops
from passlib import pwd
from passlib.apache import HtdigestFile, HtpasswdFile
from tabulate import tabulate

from charm_state import AuthenticationTypeEnum, CharmState
from charm_state_decorator import block_if_invalid_config
from exceptions import SquidPathNotFoundError

AUTH_HELPER_RELATION_NAME = "squid-auth-helper"

EVENT_FAIL_RELATION_MISSING_MESSAGE = (
    "Before running this action, integrate the charm to a Squid Reverseproxy charm."
)
STATUS_BLOCKED_RELATION_MISSING_MESSAGE = (
    "Waiting for integration with Squid Reverseproxy charm..."
)
VAULT_FILE_MISSING = "Vault file is missing, something probably went wrong during install."


class HtfileSquidAuthHelperCharm(ops.CharmBase):
    """A subordinate charm enabling support for basic or digest auth on Squid Reverseproxy."""

    def __init__(self, *args):
        """Construct the charm.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)

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

    @block_if_invalid_config
    def _on_squid_auth_helper_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        """Handle the relation created event for squid-auth-helper relation of the charm.

        Store in the relation databag the configuration parameters for the squid proxy.

        Args:
            event: Event for the squid-auth-helper relation created.
        """
        charm_state = CharmState.from_charm(self)
        event.relation.data[self.unit]["auth-params"] = json.dumps(
            self._get_charm_state_as_relation_data(charm_state)
        )
        self.unit.status = ops.ActiveStatus()

    @block_if_invalid_config
    def _on_squid_auth_helper_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle the relation broken event for squid-auth-helper relation of the charm."""
        charm_state = CharmState.from_charm(self)
        status = self._compute_charm_status()
        if not self._is_related_to_squid():
            vault_filepath = charm_state.squid_auth_config.vault_filepath
            vault_filepath.unlink()
            vault_filepath.touch(0o644, exist_ok=True)

        self.unit.status = status

    @block_if_invalid_config
    def _on_install(self, _) -> None:
        """Handle the start of the charm."""
        charm_state = CharmState.from_charm(self)

        vault_filepath = charm_state.squid_auth_config.vault_filepath
        vault_filepath.parent.mkdir(parents=True, exist_ok=True)
        vault_filepath.parent.chmod(0o755)
        vault_filepath.touch(0o644, exist_ok=True)

        self.unit.status = self._compute_charm_status()

    @block_if_invalid_config
    def _on_config_changed(self, _: ops.ConfigChangedEvent) -> None:
        """Handle configuration changes made by user."""
        charm_state = CharmState.from_charm(self)
        relations = self.model.relations[AUTH_HELPER_RELATION_NAME]

        if not relations:
            self.unit.status = ops.BlockedStatus(STATUS_BLOCKED_RELATION_MISSING_MESSAGE)
            return

        # If authentication_type has changed the vault because unparsable, we need to delete it
        try:
            self._get_auth_vault(charm_state)
        except ValueError:
            vault_filepath = charm_state.squid_auth_config.vault_filepath
            vault_filepath.unlink()
            vault_filepath.touch(0o644)

        for relation in relations:
            relation.data[self.unit]["auth-params"] = json.dumps(
                self._get_charm_state_as_relation_data(charm_state)
            )
        self.unit.status = ops.ActiveStatus()

    @block_if_invalid_config
    def _on_create_user(self, event: ops.ActionEvent) -> None:
        """Handle the create user action.

        This action allows to create a user that can be used in Squid proxy ACLs.

        Args:
            event: Event for the create user action.
        """
        charm_state = CharmState.from_charm(self)

        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        vault = self._get_auth_vault(charm_state)
        results = {}

        username = event.params["username"]
        if vault.get_hash(username):
            event.set_results({"message": f"User {username} already exists."})
            return

        generated_password = pwd.genword()
        if vault.set_password(username, generated_password):
            event.fail("An error occurred when saving the vault file.")
            return

        vault.save()
        results = {
            "username": username,
            "password": generated_password,
            "message": f"User {username} created.",
        }

        if charm_state.squid_auth_config.authentication_type == AuthenticationTypeEnum.DIGEST:
            results.update(
                {
                    "realm": charm_state.squid_auth_config.realm,
                }
            )

        event.set_results(results)

    @block_if_invalid_config
    def _on_remove_user(self, event: ops.ActionEvent) -> None:
        """Handle the remove user action.

        This action allows to remove a user that can be used in Squid proxy ACLs.
        This action fails if the user doesn't exists.

        Args:
            event: Event for the remove user action.
        """
        charm_state = CharmState.from_charm(self)

        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        vault = self._get_auth_vault(charm_state)
        results = {}

        username = event.params["username"]
        if vault.delete(username):
            results.update({"message": f"User {username} removed."})
        else:
            results.update({"message": f"User {username} doesn't exists."})

        vault.save()
        event.set_results(results)

    @block_if_invalid_config
    def _on_list_users(self, event: ops.ActionEvent) -> None:
        """Handle the list users action.

        List the users available in the Squid proxy ACLs.

        Args:
            event: Event for the list users action.
        """
        charm_state = CharmState.from_charm(self)

        if not self.model.relations[AUTH_HELPER_RELATION_NAME]:
            event.fail(EVENT_FAIL_RELATION_MISSING_MESSAGE)
            return

        vault = self._get_auth_vault(charm_state)

        user_list = {user: vault.get_hash(user) for user in vault.users()}
        headers = ["Username", "Hash password"]
        event.set_results(
            {
                "formatted": tabulate(user_list.items(), headers=headers, tablefmt="grid"),
                "list": str(user_list),
            }
        )

    def _is_related_to_squid(self) -> bool:
        """Check if the Squid proxy auth-helper relation is set.

        Returns: True if the charm is related to Squid Proxy, false otherwise
        """
        return bool(self.model.relations[AUTH_HELPER_RELATION_NAME])

    def _compute_charm_status(self) -> ops.StatusBase:
        """Set the charm to BlockedStatus if no squid-auth-helper relation exists.

        Returns: A blocked status if no relation exists, an active status otherwise.
        """
        if not self._is_related_to_squid():
            return ops.BlockedStatus(STATUS_BLOCKED_RELATION_MISSING_MESSAGE)
        return ops.ActiveStatus()

    def _get_auth_vault(self, charm_state: CharmState) -> HtdigestFile | HtpasswdFile:
        """Load the vault file in an HtdigestFile or HtpasswdFile instance.

        Args:
            charm_state: The CharmState object

        Returns: An instance of HtdigestFile or HtpasswdFile.

        Raises:
            SquidPathNotFoundError: If the digest file is missing.
        """
        if not charm_state.vault_file_exists():
            raise SquidPathNotFoundError(VAULT_FILE_MISSING)

        return (
            HtdigestFile(
                charm_state.squid_auth_config.vault_filepath,
                default_realm=charm_state.squid_auth_config.realm,
            )
            if charm_state.squid_auth_config.authentication_type == AuthenticationTypeEnum.DIGEST
            else HtpasswdFile(charm_state.squid_auth_config.vault_filepath, "sha256_crypt")
        )

    def _get_charm_state_as_relation_data(self, charm_state: CharmState) -> list[dict[str, Any]]:
        """Format the CharmState data as a dictionary for relation data.

        Args:
            charm_state: The CharmState object

        Returns: A dictionary with formatted CharmState data for the auth-helper relation.
        """
        config = charm_state.squid_auth_config
        children = (
            f"{config.children_max} startup={config.children_startup} idle={config.children_idle}"
        )
        relation_data: dict[str, str | int] = {
            "scheme": config.authentication_type.value,
            "program": charm_state.get_squid_authentication_program(),
            "children": children,
        }
        if config.authentication_type == AuthenticationTypeEnum.DIGEST:
            relation_data.update(
                {
                    "realm": config.realm,
                    "nonce_garbage_interval": f"{config.nonce_garbage_interval} minutes",
                    "nonce_max_duration": f"{config.nonce_max_duration} minutes",
                    "nonce_max_count": config.nonce_max_count,
                }
            )

        return [relation_data]


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(HtfileSquidAuthHelperCharm)
