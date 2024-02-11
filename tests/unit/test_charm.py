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
from charm_state import AuthenticationTypeEnum
from exceptions import SquidPathNotFoundError

USER = "test"
USER_CREDENTIALS = "password"


@pytest.fixture(name="digest_charm")
def digest_charm_fixture(tmp_path: Path) -> typing.Generator[Harness, None, None]:
    vault_file = Path(str(tmp_path), VAULT_FILEPATH, VAULT_FILENAME)

    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.update_config({"realm": DEFAULT_REALM, "vault_filepath": str(vault_file)})
    harness.begin_with_initial_hooks()

    yield harness

    harness.cleanup()


@pytest.fixture(name="basic_charm")
def basic_charm_fixture(tmp_path: Path) -> typing.Generator[Harness, None, None]:
    vault_file = Path(str(tmp_path), VAULT_FILEPATH, VAULT_FILENAME)

    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.update_config({"vault_filepath": str(vault_file), "authentication_type": "basic"})
    harness.begin_with_initial_hooks()

    yield harness

    harness.cleanup()


@pytest.fixture(name="configured_charm")
def configured_charm_fixture(
    request: pytest.FixtureRequest, basic_charm: Harness, digest_charm: Harness
) -> typing.Generator[Harness, None, None]:
    if request.param == "digest_charm":
        yield digest_charm
    else:
        yield basic_charm


@pytest.mark.usefixtures("tools_directory")
def test_no_relation(vault_file: Path) -> None:
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault_filepath": str(vault_file)})

    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(harness.model.unit.status)

    harness.cleanup()


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_relation(digest_charm: Harness) -> None:
    relation = digest_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    vault_file = digest_charm.charm.config["vault_filepath"]
    assert isinstance(digest_charm.model.unit.status, ops.ActiveStatus)
    assert relation

    auth_params = relation.data[digest_charm.model.unit].get("auth-params")
    assert auth_params

    loaded_auth_params = json.loads(auth_params)[0]
    assert loaded_auth_params["scheme"] == str(AuthenticationTypeEnum.DIGEST)
    assert loaded_auth_params["children"] == "20 startup=0 idle=1"

    squid_vault_file_auth = (
        f"{charm_state.SQUID_TOOLS_PATH}/{charm_state.SQUID_DIGEST_AUTH_PROGRAM}"
    )

    assert loaded_auth_params["program"] == f"{squid_vault_file_auth} -c {vault_file}"
    assert loaded_auth_params["realm"] == DEFAULT_REALM


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_relation_basic_auth(basic_charm: Harness) -> None:
    relation = basic_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    vault_file = basic_charm.charm.config["vault_filepath"]
    assert isinstance(basic_charm.model.unit.status, ops.ActiveStatus)
    assert relation

    auth_params = relation.data[basic_charm.model.unit].get("auth-params")
    assert auth_params

    loaded_auth_params = json.loads(auth_params)[0]
    assert loaded_auth_params["scheme"] == str(AuthenticationTypeEnum.BASIC)
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
    relation = digest_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    assert relation
    digest_charm.remove_relation(relation.id)

    assert isinstance(digest_charm.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(digest_charm.model.unit.status)


def test_auth_helper_squid3_folder(
    monkeypatch: pytest.MonkeyPatch, vault_file: Path, tmp_path: Path
) -> None:
    squid3_tools_path = Path(str(tmp_path), "tools", "squid3")
    squid3_tools_path.mkdir(parents=True)

    monkeypatch.setattr(charm_state, "SQUID_TOOLS_PATH", Path(str(tmp_path), "tools", "squid"))
    monkeypatch.setattr(charm_state, "SQUID3_TOOLS_PATH", squid3_tools_path)

    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.update_config({"vault_filepath": str(vault_file)})
    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.ActiveStatus)

    harness.cleanup()


def test_auth_helper_no_squid_folder() -> None:
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
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with(
        {"username": USER, "password": unittest.mock.ANY, "realm": DEFAULT_REALM}
    )
    vault.path = configured_charm.charm.config["vault_filepath"]
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
    vault.path = configured_charm.charm.config["vault_filepath"]
    vault.set_password(USER, USER_CREDENTIALS)
    vault.save()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with({"success": True})

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
    username2 = f"{USER}2"

    vault.path = configured_charm.charm.config["vault_filepath"]
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
    vault.path = configured_charm.charm.config["vault_filepath"]
    vault.set_password(USER, USER_CREDENTIALS)
    vault.save()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} already exists.")


@pytest.mark.usefixtures("tools_directory")
def test_create_user_set_password_fails(
    digest_charm: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_set_password = unittest.mock.MagicMock()
    mock_set_password.return_value = True
    monkeypatch.setattr(charm_state.HtdigestFile, "set_password", mock_set_password)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    digest_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with("An error occurred when saving the vault file.")


@pytest.mark.usefixtures("tools_directory")
def test_create_user_no_relation(vault_file: Path) -> None:
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault_filepath": str(vault_file)})
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
    vault_file = Path(digest_charm.charm.config["vault_filepath"])
    vault_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(SquidPathNotFoundError) as exc:
        digest_charm.charm._on_create_user(event)

    assert charm_state.VAULT_FILE_MISSING in str(exc.value.msg)


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
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} doesn't exists.")


@pytest.mark.usefixtures("tools_directory")
def test_remove_user_no_relation(vault_file: Path) -> None:
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault_filepath": str(vault_file)})
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
    vault_file = Path(digest_charm.charm.config["vault_filepath"])
    vault_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(SquidPathNotFoundError) as exc:
        digest_charm.charm._on_remove_user(event)

    assert charm_state.VAULT_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("tools_directory")
def test_list_users_no_relation(vault_file: Path) -> None:
    harness = Harness(charm.HtfileSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "vault_filepath": str(vault_file)})
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    harness.charm._on_list_users(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("tools_directory")
def test_list_users_no_vault_file(digest_charm: Harness) -> None:
    vault_file = Path(digest_charm.charm.config["vault_filepath"])
    vault_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    with pytest.raises(SquidPathNotFoundError) as exc:
        digest_charm.charm._on_list_users(event)

    assert charm_state.VAULT_FILE_MISSING in str(exc.value.msg)
