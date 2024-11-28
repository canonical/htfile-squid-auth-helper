# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more about testing at: https://juju.is/docs/sdk/testing

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
"""Unit tests."""

import json
import typing
import unittest.mock
from pathlib import Path

import ops
import pytest
from ops.testing import Harness
from passlib.apache import HtdigestFile, HtpasswdFile
from unit.constants import DEFAULT_REALM, VAULT_FILENAME, VAULT_FILEPATH

import charm
import charm_state
from charm_state import AuthenticationTypeEnum, CharmState
from exceptions import SquidPathNotFoundError

USER = "test"
USER_CREDENTIALS = "password"


@pytest.fixture(name="digest_charm")
def digest_charm_fixture(tmp_path: Path) -> typing.Generator[Harness, None, None]:
    """Harness fixture with Digest file in a temporary directory.

    Args:
        tmp_path: A temporary directory where the vault file will be stored.

    Returns:
        Harness fixture.
    """
    vault_file = Path(str(tmp_path), VAULT_FILEPATH, VAULT_FILENAME)

    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.update_config({"realm": DEFAULT_REALM, "vault-filepath": str(vault_file)})
    harness.begin_with_initial_hooks()

    yield harness

    harness.cleanup()


@pytest.fixture(name="basic_charm")
def basic_charm_fixture(tmp_path: Path) -> typing.Generator[Harness, None, None]:
    """Harness fixture with Basic htfile in a temporary directory.

    Args:
        tmp_path: A temporary directory where the vault file will be stored.

    Returns:
        Harness fixture.
    """
    vault_file = Path(str(tmp_path), VAULT_FILEPATH, VAULT_FILENAME)

    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.update_config({"vault-filepath": str(vault_file), "authentication-type": "basic"})
    harness.begin_with_initial_hooks()

    yield harness

    harness.cleanup()


@pytest.fixture(name="configured_charm")
def configured_charm_fixture(
    request: pytest.FixtureRequest, basic_charm: Harness, digest_charm: Harness
) -> typing.Generator[Harness, None, None]:
    """Harness fixture with either Digest or Basic file depending on fixture parameter."""
    if request.param == "digest_charm":
        yield digest_charm
    else:
        yield basic_charm


@pytest.mark.usefixtures("tools_directory")
def test_no_relation(vault_file: Path) -> None:
    """
    arrange: A temporary path for the vault file.
    act: Start the charm without any relation.
    assert: The unit should be in the expected state with the expected message.
    """
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault-filepath": str(vault_file)})

    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(harness.model.unit.status)

    harness.cleanup()


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_relation(digest_charm: Harness) -> None:
    """
    arrange: Start the charm with digest as authentication_type.
    act: Get the relation data.
    assert: The unit should be in the expected state
        and the relation data should be what we expect.
    """
    relation = digest_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    vault_file = digest_charm.charm.config["vault-filepath"]
    assert isinstance(digest_charm.model.unit.status, ops.ActiveStatus)
    assert relation

    auth_params = relation.data[digest_charm.model.unit].get("auth-params")
    assert auth_params

    loaded_auth_params = json.loads(auth_params)[0]
    assert loaded_auth_params["scheme"] == AuthenticationTypeEnum.DIGEST.value
    assert loaded_auth_params["children"] == "20 startup=0 idle=1"

    squid_vault_file_auth = (
        f"{charm_state.SQUID_TOOLS_PATH}/{charm_state.SQUID_DIGEST_AUTH_PROGRAM}"
    )

    assert loaded_auth_params["program"] == f"{squid_vault_file_auth} -c {vault_file}"
    assert loaded_auth_params["realm"] == DEFAULT_REALM


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_relation_basic_auth(basic_charm: Harness) -> None:
    """
    arrange: Start the charm with basic as authentication_type.
    act: Get the relation data.
    assert: The unit should be in the expected state
        and the relation data should be what we expect.
    """
    relation = basic_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    vault_file = basic_charm.charm.config["vault-filepath"]
    assert isinstance(basic_charm.model.unit.status, ops.ActiveStatus)
    assert relation

    auth_params = relation.data[basic_charm.model.unit].get("auth-params")
    assert auth_params

    loaded_auth_params = json.loads(auth_params)[0]
    assert loaded_auth_params["scheme"] == AuthenticationTypeEnum.BASIC.value
    assert loaded_auth_params["children"] == "20 startup=0 idle=1"

    squid_vault_file_auth = (
        f"{charm_state.SQUID_TOOLS_PATH}/{charm_state.SQUID_BASIC_AUTH_PROGRAM}"
    )

    assert loaded_auth_params["program"] == f"{squid_vault_file_auth} {vault_file}"
    assert not loaded_auth_params.get("realm")
    assert not loaded_auth_params.get("nonce_garbage_interval")
    assert not loaded_auth_params.get("nonce_max_count")
    assert not loaded_auth_params.get("nonce_max_duration")


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_no_more_relation(digest_charm: Harness) -> None:
    """
    arrange: Start the charm with digest as authentication_type and a user created.
    act: Remove the existing relation.
    assert: The unit should be in the expected state with the expected message
        and the vault_file should be empty.
    """
    # Add data in the file
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}
    digest_charm.charm._on_create_user(event)

    relation = digest_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    assert relation
    digest_charm.remove_relation(relation.id)

    assert isinstance(digest_charm.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(digest_charm.model.unit.status)

    # Vault file is emptied
    vault = digest_charm.charm._get_auth_vault(CharmState.from_charm(digest_charm.charm))
    assert vault
    assert not vault.users()


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_more_than_one_relation(digest_charm: Harness) -> None:
    """
    arrange: Start the charm with digest as authentication_type, a user created
        and more than one relation.
    act: Remove the first relation.
    assert: The unit should be in the expected state
        and the vault_file should still contain the user.
    """
    # Add data in the file
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}
    digest_charm.charm._on_create_user(event)

    # Add additional relation
    digest_charm.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy2")

    relation = digest_charm.model.relations
    assert len(relation[charm.AUTH_HELPER_RELATION_NAME]) == 2
    assert isinstance(digest_charm.model.unit.status, ops.ActiveStatus)

    # Remove first relation
    digest_charm.remove_relation(relation[charm.AUTH_HELPER_RELATION_NAME][0].id)

    assert isinstance(digest_charm.model.unit.status, ops.ActiveStatus)
    # Vault file is kept
    vault = digest_charm.charm._get_auth_vault(CharmState.from_charm(digest_charm.charm))
    assert vault
    assert vault.users()


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_authentication_type_changed(digest_charm: Harness) -> None:
    """
    arrange: Start the charm with digest as authentication_type and a user created.
    act: Change the authentication_type config to basic.
    assert: The vault_file should be empty.
    """
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    digest_charm.charm._on_create_user(event)

    digest_charm.update_config({"authentication-type": "basic"})

    # Vault file is emptied
    vault = digest_charm.charm._get_auth_vault(CharmState.from_charm(digest_charm.charm))
    assert vault
    assert not vault.users()


def test_auth_helper_no_squid_folder() -> None:
    """
    arrange: No squid folder created.
    act: Start the charm.
    assert: The charm should raise the expected exception with the expected message.
    """
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    with pytest.raises(SquidPathNotFoundError) as err:
        harness.begin_with_initial_hooks()

    assert "Squid tools path can't be found" in str(err.value.msg)


@pytest.mark.usefixtures("tools_directory")
@pytest.mark.parametrize(
    "configured_charm, vault",
    [
        pytest.param("digest_charm", HtdigestFile(default_realm=DEFAULT_REALM), id="with digest"),
        pytest.param("basic_charm", HtpasswdFile(default_scheme="sha256_crypt"), id="with basic"),
    ],
    indirect=["configured_charm"],
)
def test_create_user_action(configured_charm: Harness, vault: HtdigestFile | HtpasswdFile) -> None:
    """
    arrange: Start the charm with digest or basic as authentication_type.
    act: Create a user.
    assert: The user should be available in the vault file and charm has the expected status.
    """
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.set_results.call_count == 1
    asserted_args = {
        "username": USER,
        "password": unittest.mock.ANY,
        "message": f"User {USER} created.",
    }
    if isinstance(vault, HtdigestFile):
        asserted_args.update({"realm": DEFAULT_REALM})
    event.set_results.assert_called_with(asserted_args)

    vault.path = configured_charm.charm.config["vault-filepath"]
    vault.load()
    assert vault.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


@pytest.mark.usefixtures("tools_directory")
@pytest.mark.parametrize(
    "configured_charm, vault",
    [
        pytest.param("digest_charm", HtdigestFile(default_realm=DEFAULT_REALM), id="with digest"),
        pytest.param("basic_charm", HtpasswdFile(default_scheme="sha256_crypt"), id="with basic"),
    ],
    indirect=["configured_charm"],
)
def test_remove_user_action(configured_charm: Harness, vault: HtdigestFile | HtpasswdFile) -> None:
    """
    arrange: Start the charm with digest or basic as authentication_type and a user created.
    act: Remove the user.
    assert: The unit should be in the expected state and the user should not exist in the vault.
    """
    vault.path = configured_charm.charm.config["vault-filepath"]
    vault.set_password(USER, USER_CREDENTIALS)
    vault.save()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with({"message": f"User {USER} removed."})

    # Reload from the file as the charm altered the vault file
    vault.load()

    assert not vault.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


@pytest.mark.usefixtures("tools_directory")
@pytest.mark.parametrize(
    "configured_charm, vault",
    [
        pytest.param("digest_charm", HtdigestFile(default_realm=DEFAULT_REALM), id="with digest"),
        pytest.param("basic_charm", HtpasswdFile(default_scheme="sha256_crypt"), id="with basic"),
    ],
    indirect=["configured_charm"],
)
def test_list_users(configured_charm: Harness, vault: HtdigestFile | HtpasswdFile) -> None:
    """
    arrange: Start the charm with digest or basic as authentication_type and two users created.
    act: Run the list users action.
    assert: The action should return the two users.
    """
    username2 = f"{USER}2"

    vault.path = configured_charm.charm.config["vault-filepath"]
    vault.set_password(USER, USER_CREDENTIALS)
    vault.set_password(username2, USER_CREDENTIALS)
    vault.save()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    configured_charm.charm._on_list_users(event)

    assert event.set_results.call_count == 1

    set_result_args = event.set_results.call_args.args[0]
    assert set_result_args
    assert USER in set_result_args["formatted"]
    assert USER in set_result_args["list"]
    assert username2 in set_result_args["formatted"]
    assert username2 in set_result_args["list"]


@pytest.mark.usefixtures("tools_directory")
@pytest.mark.parametrize(
    "configured_charm, vault",
    [
        pytest.param("digest_charm", HtdigestFile(default_realm=DEFAULT_REALM), id="with digest"),
        pytest.param("basic_charm", HtpasswdFile(default_scheme="sha256_crypt"), id="with basic"),
    ],
    indirect=["configured_charm"],
)
def test_create_user_already_exists(
    configured_charm: Harness, vault: HtdigestFile | HtpasswdFile
) -> None:
    """
    arrange: Start the charm with digest or basic as authentication_type and a user created.
    act: Create a new user with the same username as the existing one.
    assert: The action should succeed with the expected message.
    """
    vault.path = configured_charm.charm.config["vault-filepath"]
    vault.set_password(USER, USER_CREDENTIALS)
    vault.save()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with({"message": f"User {USER} already exists."})


@pytest.mark.usefixtures("tools_directory")
def test_create_user_set_password_fails(
    digest_charm: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    arrange: Start the charm with digest authentication_type
        and with a failing mocked set_password method.
    act: Create a user.
    assert: The action should fail with the expected message.
    """
    mock_set_password = unittest.mock.MagicMock()
    mock_set_password.return_value = True
    monkeypatch.setattr(charm.HtdigestFile, "set_password", mock_set_password)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    digest_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with("An error occurred when saving the vault file.")


@pytest.mark.usefixtures("tools_directory")
def test_create_user_no_relation(vault_file: Path) -> None:
    """
    arrange: Start the charm with digest authentication_type but no relations.
    act: Create a user.
    assert: The action should fail with the expected message
        and the unit should be in the expected state.
    """
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault-filepath": str(vault_file)})
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    harness.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("tools_directory")
def test_create_user_no_vault_file(digest_charm: Harness) -> None:
    """
    arrange: Start the charm with digest authentication_type and the vault file missing.
    act: Create a user.
    assert: An exception should be raised with the expected message.
    """
    vault_file = Path(digest_charm.charm.config["vault-filepath"])
    vault_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(SquidPathNotFoundError) as exc:
        digest_charm.charm._on_create_user(event)

    assert charm.VAULT_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("tools_directory")
@pytest.mark.parametrize(
    "configured_charm",
    [
        pytest.param("digest_charm", id="with digest"),
        pytest.param("basic_charm", id="with basic"),
    ],
    indirect=["configured_charm"],
)
def test_remove_user_doesnt_exists(configured_charm: Harness) -> None:
    """
    arrange: Start the charm with digest or basic authentication_type and no user created.
    act: Remove a user.
    assert: The action should succeed with the expected message..
    """
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with({"message": f"User {USER} doesn't exists."})


@pytest.mark.usefixtures("tools_directory")
def test_remove_user_no_relation(vault_file: Path) -> None:
    """
    arrange: Start the charm with digest authentication_type but no relations.
    act: Remove a user.
    assert: The action should fail with the expected message
        and the unit should be in the expected state.
    """
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault-filepath": str(vault_file)})
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    harness.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("tools_directory")
def test_remove_user_no_vault_file(digest_charm: Harness) -> None:
    """
    arrange: Start the charm with digest authentication_type and the vault file missing.
    act: Remove a user.
    assert: An exception should be raised with the expected message.
    """
    vault_file = Path(digest_charm.charm.config["vault-filepath"])
    vault_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(SquidPathNotFoundError) as exc:
        digest_charm.charm._on_remove_user(event)

    assert charm.VAULT_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("tools_directory")
def test_list_users_no_relation(vault_file: Path) -> None:
    """
    arrange: Start the charm with digest authentication_type but no relations.
    act: Call list users action.
    assert: The action should fail with the expected message
        and the unit should be in the expected state.
    """
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault-filepath": str(vault_file)})
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    harness.charm._on_list_users(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("tools_directory")
def test_list_users_no_vault_file(digest_charm: Harness) -> None:
    """
    arrange: Start the charm with digest authentication_type and the vault file missing.
    act: Call list users action.
    assert: An exception should be raised with the expected message.
    """
    vault_file = Path(digest_charm.charm.config["vault-filepath"])
    vault_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    with pytest.raises(SquidPathNotFoundError) as exc:
        digest_charm.charm._on_list_users(event)

    assert charm.VAULT_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_get_digest(digest_charm: Harness) -> None:
    """
    arrange: A charmstate with default authentication_type (digest).
    act: Get the vault from get_auth_vault method.
    assert: The vault should be an instance of HtdigestFile.
    """
    vault = digest_charm.charm._get_auth_vault(CharmState.from_charm(digest_charm.charm))

    assert isinstance(vault, HtdigestFile)


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_get_basic(basic_charm: Harness) -> None:
    """
    arrange: A charmstate with basic as authentication_type.
    act: Get the vault from get_auth_vault method.
    assert: The vault should be an instance of HtpasswdFile.
    """
    vault = basic_charm.charm._get_auth_vault(CharmState.from_charm(basic_charm.charm))

    assert isinstance(vault, HtpasswdFile)


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_get_vault_no_file(digest_charm: Harness) -> None:
    """
    arrange: A charmstate with default authentication_type (digest) but missing vault file.
    act: Get the vault from get_auth_vault method.
    assert: The expected exception should be raised with the expected message.
    """
    state = CharmState.from_charm(digest_charm.charm)
    vault_file = state.squid_auth_config.vault_filepath
    vault_file.unlink()
    with pytest.raises(SquidPathNotFoundError) as exc:
        digest_charm.charm._get_auth_vault(state)

    assert charm.VAULT_FILE_MISSING == exc.value.msg
