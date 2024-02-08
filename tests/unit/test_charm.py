# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more about testing at: https://juju.is/docs/sdk/testing

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
"""Unit tests."""

import json
import typing
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

import ops
import pytest
from ops.testing import Harness
from passlib.apache import HtdigestFile
from unit.constants import DEFAULT_REALM, DIGEST_FILENAME, DIGEST_FILEPATH

import charm
import charm_state
from exceptions import SquidPathNotFoundError

USER = "test"
USER_CREDENTIALS = "password"


@pytest.fixture(name="configured_charm")
def configured_charm_fixture() -> typing.Generator[Harness, None, None]:
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()
    digest_file = Path(tmp_digest_dir.name, DIGEST_FILEPATH, DIGEST_FILENAME)

    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.update_config({"realm": DEFAULT_REALM, "digest_filepath": str(digest_file)})
    harness.begin_with_initial_hooks()

    yield harness

    harness.cleanup()
    tmp_digest_dir.cleanup()


@pytest.mark.usefixtures("tools_directory")
def test_no_relation(digest_file: Path) -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "digest_filepath": str(digest_file)})

    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(harness.model.unit.status)

    harness.cleanup()


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_relation(configured_charm: Harness) -> None:
    relation = configured_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    digest_file = configured_charm.charm.config["digest_filepath"]
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)
    assert relation

    auth_params = relation.data[configured_charm.model.unit].get("auth-params")
    assert auth_params

    loaded_auth_params = json.loads(auth_params)[0]
    assert loaded_auth_params["scheme"] == "digest"
    assert loaded_auth_params["children"] == "20 startup=0 idle=1"

    squid_digest_file_auth = f"{charm_state.SQUID_TOOLS_PATH}/digest_file_auth"

    assert loaded_auth_params["program"] == f"{squid_digest_file_auth} -c {digest_file}"
    assert loaded_auth_params["realm"] == DEFAULT_REALM


@pytest.mark.usefixtures("tools_directory")
def test_auth_helper_no_more_relation(configured_charm: Harness) -> None:
    relation = configured_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    assert relation
    configured_charm.remove_relation(relation.id)

    assert isinstance(configured_charm.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(configured_charm.model.unit.status)


def test_auth_helper_squid3_folder(monkeypatch: pytest.MonkeyPatch, digest_file: Path) -> None:
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()

    squid3_tools_path = Path(tmp_digest_dir.name, "tools", "squid3")
    squid3_tools_path.mkdir(parents=True)

    monkeypatch.setattr(
        charm_state, "SQUID_TOOLS_PATH", Path(tmp_digest_dir.name, "tools", "squid")
    )
    monkeypatch.setattr(charm_state, "SQUID3_TOOLS_PATH", squid3_tools_path)

    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.update_config({"digest_filepath": str(digest_file)})
    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.ActiveStatus)

    tmp_digest_dir.cleanup()
    harness.cleanup()


def test_auth_helper_no_squid_folder() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    with pytest.raises(SquidPathNotFoundError) as err:
        harness.begin_with_initial_hooks()

    assert "Squid tools path can't be found" in str(err.value.msg)


@pytest.mark.usefixtures("tools_directory")
def test_create_user_action(configured_charm: Harness) -> None:
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with(
        {"username": USER, "password": unittest.mock.ANY, "realm": DEFAULT_REALM}
    )

    digest = HtdigestFile(
        configured_charm.charm.config["digest_filepath"], default_realm=DEFAULT_REALM
    )

    assert digest.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


@pytest.mark.usefixtures("tools_directory")
def test_remove_user_action(configured_charm: Harness) -> None:
    digest = HtdigestFile(
        configured_charm.charm.config["digest_filepath"], default_realm=DEFAULT_REALM
    )
    digest.set_password(USER, USER_CREDENTIALS)
    digest.save()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with({"success": True})

    # Reload from the file as the charm altered the digest file
    digest.load()

    assert not digest.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


@pytest.mark.usefixtures("tools_directory")
def test_list_users(configured_charm: Harness) -> None:
    username2 = f"{USER}2"

    digest = HtdigestFile(
        configured_charm.charm.config["digest_filepath"], default_realm=DEFAULT_REALM
    )
    digest.set_password(USER, USER_CREDENTIALS)
    digest.set_password(username2, USER_CREDENTIALS)
    digest.save()

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
def test_create_user_already_exists(configured_charm: Harness) -> None:
    digest = HtdigestFile(
        configured_charm.charm.config["digest_filepath"], default_realm=DEFAULT_REALM
    )
    digest.set_password(USER, USER_CREDENTIALS)
    digest.save()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} already exists.")


@pytest.mark.usefixtures("tools_directory")
def test_create_user_set_password_fails(
    configured_charm: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_set_password = unittest.mock.MagicMock()
    mock_set_password.return_value = True
    monkeypatch.setattr(charm_state.HtdigestFile, "set_password", mock_set_password)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with("An error occurred when saving the htdigest file.")


@pytest.mark.usefixtures("tools_directory")
def test_create_user_no_relation(digest_file: Path) -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "digest_filepath": str(digest_file)})
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    harness.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("tools_directory")
def test_create_user_no_digest_file(configured_charm: Harness) -> None:
    digest_file = Path(configured_charm.charm.config["digest_filepath"])
    digest_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(SquidPathNotFoundError) as exc:
        configured_charm.charm._on_create_user(event)

    assert charm_state.HTDIGEST_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("tools_directory")
def test_remove_user_doesnt_exists(configured_charm: Harness) -> None:
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} doesn't exists.")


@pytest.mark.usefixtures("tools_directory")
def test_remove_user_no_relation(digest_file: Path) -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "digest_filepath": str(digest_file)})
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    harness.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("tools_directory")
def test_remove_user_no_digest_file(configured_charm: Harness) -> None:
    digest_file = Path(configured_charm.charm.config["digest_filepath"])
    digest_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(SquidPathNotFoundError) as exc:
        configured_charm.charm._on_remove_user(event)

    assert charm_state.HTDIGEST_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("tools_directory")
def test_list_users_no_relation(digest_file: Path) -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.update_config({"realm": DEFAULT_REALM, "digest_filepath": str(digest_file)})
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    harness.charm._on_list_users(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("tools_directory")
def test_list_users_no_digest_file(configured_charm: Harness) -> None:
    digest_file = Path(configured_charm.charm.config["digest_filepath"])
    digest_file.unlink()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    with pytest.raises(SquidPathNotFoundError) as exc:
        configured_charm.charm._on_list_users(event)

    assert charm_state.HTDIGEST_FILE_MISSING in str(exc.value.msg)
