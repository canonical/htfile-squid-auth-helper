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

import charm

USER = "test"
USER_CREDENTIALS = "password"


@pytest.fixture(name="fake_fs")
def fake_fs_fixture(monkeypatch: pytest.MonkeyPatch) -> typing.Generator[None, None, None]:
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()

    squid_config_path = Path(tmp_digest_dir.name, "etc", "squid-auth")
    squid_config_path.mkdir(parents=True)

    squid_tools_path = Path(tmp_digest_dir.name, "tools", "squid")
    squid_tools_path.mkdir(parents=True)

    monkeypatch.setattr(charm, "DIGEST_FILEPATH", squid_config_path.joinpath("password-file"))
    monkeypatch.setattr(charm, "SQUID_TOOLS_PATH", squid_tools_path)
    monkeypatch.setattr(charm, "SQUID3_TOOLS_PATH", Path(tmp_digest_dir.name, "tools", "squid3"))

    squid_config_path.joinpath(charm.DIGEST_FILEPATH).touch(exist_ok=True)

    yield

    tmp_digest_dir.cleanup()


@pytest.fixture(name="configured_charm")
def configured_charm_fixture() -> typing.Generator[Harness, None, None]:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.begin_with_initial_hooks()

    yield harness
    harness.cleanup()


def test_no_relation(monkeypatch: pytest.MonkeyPatch) -> None:
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()

    squid_config_path = Path(tmp_digest_dir.name, "etc", "squid")
    squid_config_path.mkdir(parents=True)

    squid_tools_path = Path(tmp_digest_dir.name, "tools", "squid")
    squid_tools_path.mkdir(parents=True)

    monkeypatch.setattr(charm, "DIGEST_FILEPATH", squid_config_path.joinpath("password-file"))
    monkeypatch.setattr(charm, "SQUID_TOOLS_PATH", squid_tools_path)
    monkeypatch.setattr(charm, "SQUID3_TOOLS_PATH", Path(tmp_digest_dir.name, "tools", "squid3"))

    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(harness.model.unit.status)

    tmp_digest_dir.cleanup()
    harness.cleanup()


@pytest.mark.usefixtures("fake_fs")
def test_auth_helper_relation(configured_charm: Harness) -> None:
    # This import is needed here after patching it in the fixture
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    relation = configured_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)
    assert relation

    auth_params = relation.data[configured_charm.model.unit].get("auth-params")
    assert auth_params

    loaded_auth_params = json.loads(auth_params)[0]
    assert loaded_auth_params["scheme"] == "digest"
    assert loaded_auth_params["children"] == "20 startup=0 idle=1"

    squid_digest_file_auth = f"{configured_charm.charm._squid_tools_path}/digest_file_auth"

    print(loaded_auth_params["program"])
    assert loaded_auth_params["program"] == f"{squid_digest_file_auth} -c {DIGEST_FILEPATH}"
    assert loaded_auth_params["realm"] == charm.DIGEST_REALM


@pytest.mark.usefixtures("fake_fs")
def test_auth_helper_no_more_relation(configured_charm: Harness) -> None:
    relation = configured_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    assert relation
    configured_charm.remove_relation(relation.id)

    assert isinstance(configured_charm.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(configured_charm.model.unit.status)


def test_auth_helper_squid3_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()

    squid3_tools_path = Path(tmp_digest_dir.name, "tools", "squid3")
    squid3_tools_path.mkdir(parents=True)

    monkeypatch.setattr(
        charm, "DIGEST_FILEPATH", Path(tmp_digest_dir.name, "etc", "squid-auth", "password-file")
    )
    monkeypatch.setattr(charm, "SQUID_TOOLS_PATH", Path(tmp_digest_dir.name, "tools", "squid"))
    monkeypatch.setattr(charm, "SQUID3_TOOLS_PATH", squid3_tools_path)

    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.ActiveStatus)

    tmp_digest_dir.cleanup()
    harness.cleanup()


def test_auth_helper_no_squid_folder() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    with pytest.raises(charm.SquidPathNotFoundError) as err:
        harness.begin_with_initial_hooks()

    assert "Squid tools path can't be found" in str(err.value.msg)


@pytest.mark.usefixtures("fake_fs")
def test_create_user_action(configured_charm: Harness) -> None:
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with(
        {"username": USER, "password": unittest.mock.ANY, "realm": charm.DIGEST_REALM}
    )
    assert configured_charm.charm._digest.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


@pytest.mark.usefixtures("fake_fs")
def test_remove_user_action(configured_charm: Harness) -> None:
    # This import is needed here after patching it in the fixture
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    configured_charm.charm._digest.set_password(USER, USER_CREDENTIALS)
    configured_charm.charm._digest.save(DIGEST_FILEPATH)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with({"success": True})
    assert not configured_charm.charm._digest.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


@pytest.mark.usefixtures("fake_fs")
def test_list_users(configured_charm: Harness) -> None:
    # This import is needed here after patching it in the fixture
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    username2 = f"{USER}2"

    configured_charm.charm._digest.set_password(USER, USER_CREDENTIALS)
    configured_charm.charm._digest.set_password(username2, USER_CREDENTIALS)
    configured_charm.charm._digest.save(DIGEST_FILEPATH)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    configured_charm.charm._on_list_users(event)

    assert event.set_results.call_count == 1

    set_result_args = event.set_results.call_args.args[0]
    assert set_result_args
    assert USER in set_result_args["formatted"]
    assert USER in set_result_args["list"]
    assert username2 in set_result_args["formatted"]
    assert username2 in set_result_args["list"]


@pytest.mark.usefixtures("fake_fs")
def test_create_user_already_exists(configured_charm: Harness) -> None:
    # This import is needed here after patching it in the fixture
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    configured_charm.charm._digest.set_password(USER, USER_CREDENTIALS)
    configured_charm.charm._digest.save(DIGEST_FILEPATH)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} already exists.")


@pytest.mark.usefixtures("fake_fs")
def test_create_user_set_password_fails(
    configured_charm: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_set_password = unittest.mock.MagicMock()
    mock_set_password.return_value = True
    monkeypatch.setattr(configured_charm.charm._digest, "set_password", mock_set_password)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with("An error occurred when saving the htdigest file.")


@pytest.mark.usefixtures("fake_fs")
def test_create_user_no_relation() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    harness.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("fake_fs")
def test_create_user_no_digest_file(configured_charm: Harness) -> None:
    configured_charm.charm._digest = None

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(charm.SquidPathNotFoundError) as exc:
        configured_charm.charm._on_create_user(event)

    assert charm.EVENT_FAIL_HTDIGEST_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("fake_fs")
def test_remove_user_doesnt_exists(configured_charm: Harness) -> None:
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    configured_charm.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} doesn't exists.")


@pytest.mark.usefixtures("fake_fs")
def test_remove_user_no_relation() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    harness.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("fake_fs")
def test_remove_user_no_digest_file(configured_charm: Harness) -> None:
    configured_charm.charm._digest = None

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    with pytest.raises(charm.SquidPathNotFoundError) as exc:
        configured_charm.charm._on_remove_user(event)

    assert charm.EVENT_FAIL_HTDIGEST_FILE_MISSING in str(exc.value.msg)


@pytest.mark.usefixtures("fake_fs")
def test_list_users_no_relation() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    harness.charm._on_list_users(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


@pytest.mark.usefixtures("fake_fs")
def test_list_users_no_digest_file(configured_charm: Harness) -> None:
    configured_charm.charm._digest = None

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    with pytest.raises(charm.SquidPathNotFoundError) as exc:
        configured_charm.charm._on_list_users(event)

    assert charm.EVENT_FAIL_HTDIGEST_FILE_MISSING in str(exc.value.msg)
