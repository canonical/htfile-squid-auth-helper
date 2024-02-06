# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more about testing at: https://juju.is/docs/sdk/testing

# pylint: disable=duplicate-code,missing-function-docstring
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


@pytest.fixture(name="configured_charm")
def configured_charm_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> typing.Generator[Harness, None, None]:
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()
    tmp_digest_file = Path(tmp_digest_dir.name, "squid3", "password-file")

    monkeypatch.setattr(charm, "DIGEST_FILEPATH", tmp_digest_file)

    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.set_leader(True)
    harness.add_relation(charm.AUTH_HELPER_RELATION_NAME, "squid-reverseproxy")
    harness.begin_with_initial_hooks()

    yield harness
    harness.cleanup()
    tmp_digest_dir.cleanup()


def test_no_relation() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    assert isinstance(harness.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(harness.model.unit.status)


def test_auth_helper_relation(configured_charm: Harness) -> None:
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    relation = configured_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)
    assert relation

    auth_params = relation.data[configured_charm.model.app].get("auth-params")
    assert auth_params

    loaded_auth_params = json.loads(auth_params)[0]
    assert loaded_auth_params["scheme"] == "digest"
    assert loaded_auth_params["children"] == 5
    assert loaded_auth_params["program"] == f"/usr/lib/squid3/digest_pw_auth -c {DIGEST_FILEPATH}"


def test_auth_helper_no_more_relation(configured_charm: Harness) -> None:
    relation = configured_charm.model.get_relation(charm.AUTH_HELPER_RELATION_NAME)
    assert relation
    configured_charm.remove_relation(relation.id)

    assert isinstance(configured_charm.model.unit.status, ops.BlockedStatus)
    assert charm.STATUS_BLOCKED_RELATION_MISSING_MESSAGE in str(configured_charm.model.unit.status)


def test_create_user_action(configured_charm: Harness) -> None:
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    # pylint: disable=protected-access
    configured_charm.charm._on_create_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with(
        {"username": USER, "password": unittest.mock.ANY, "realm": charm.DIGEST_REALM}
    )
    assert configured_charm.charm.digest.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


def test_remove_user_action(configured_charm: Harness) -> None:
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    configured_charm.charm.digest.set_password(USER, USER_CREDENTIALS)
    configured_charm.charm.digest.save(DIGEST_FILEPATH)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    # pylint: disable=protected-access
    configured_charm.charm._on_remove_user(event)

    assert event.set_results.call_count == 1
    event.set_results.assert_called_with({"success": True})
    assert not configured_charm.charm.digest.get_hash(USER)
    assert isinstance(configured_charm.model.unit.status, ops.ActiveStatus)


def test_list_users(configured_charm: Harness) -> None:
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    username2 = f"{USER}2"

    configured_charm.charm.digest.set_password(USER, USER_CREDENTIALS)
    configured_charm.charm.digest.set_password(username2, USER_CREDENTIALS)
    configured_charm.charm.digest.save(DIGEST_FILEPATH)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    # pylint: disable=protected-access
    configured_charm.charm._on_list_users(event)

    assert event.set_results.call_count == 1

    set_result_args = event.set_results.call_args.args[0]
    assert set_result_args
    assert USER in set_result_args["formatted"]
    assert USER in set_result_args["list"]
    assert username2 in set_result_args["formatted"]
    assert username2 in set_result_args["list"]


def test_create_user_already_exists(configured_charm: Harness) -> None:
    # pylint: disable=import-outside-toplevel
    from charm import DIGEST_FILEPATH

    configured_charm.charm.digest.set_password(USER, USER_CREDENTIALS)
    configured_charm.charm.digest.save(DIGEST_FILEPATH)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    # pylint: disable=protected-access
    configured_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} already exists.")


def test_create_user_set_password_fails(
    configured_charm: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_set_password = unittest.mock.MagicMock()
    mock_set_password.return_value = True
    monkeypatch.setattr(configured_charm.charm.digest, "set_password", mock_set_password)

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    # pylint: disable=protected-access
    configured_charm.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with("An error occurred when saving the htdigest file.")


def test_create_user_no_relation() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    # pylint: disable=protected-access
    harness.charm._on_create_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


def test_remove_user_doesnt_exists(configured_charm: Harness) -> None:
    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    # pylint: disable=protected-access
    configured_charm.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(f"User {USER} doesn't exists.")


def test_remove_user_no_relation() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)
    event.params = {"username": USER}

    # pylint: disable=protected-access
    harness.charm._on_remove_user(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)


def test_list_users_no_relation() -> None:
    harness = Harness(charm.DigestSquidAuthHelperCharm)
    harness.begin_with_initial_hooks()

    event = unittest.mock.MagicMock(spec=ops.ActionEvent)

    # pylint: disable=protected-access
    harness.charm._on_list_users(event)

    assert event.fail.call_count == 1
    assert event.set_results.call_count == 0
    event.fail.assert_called_with(charm.EVENT_FAIL_RELATION_MISSING_MESSAGE)
    assert isinstance(harness.model.unit.status, ops.BlockedStatus)
