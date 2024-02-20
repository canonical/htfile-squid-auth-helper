# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more about testing at: https://juju.is/docs/sdk/testing

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
"""Unit tests."""


from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest
from ops import CharmBase
from passlib.apache import HtdigestFile, HtpasswdFile
from unit.constants import DEFAULT_REALM, VAULT_FILENAME, VAULT_FILEPATH

import charm_state
from charm_state import VAULT_FILE_MISSING, AuthenticationTypeEnum, CharmState, SquidAuthConfig
from exceptions import CharmConfigInvalidError, SquidPathNotFoundError


@pytest.fixture(name="mocked_charm")
def mocked_charm_fixture() -> Generator[CharmBase, None, None]:
    """A mocked charm fixture."""
    vault_filepath = VAULT_FILEPATH.joinpath(VAULT_FILENAME)
    digest_realm = DEFAULT_REALM
    config = {"vault_filepath": vault_filepath, "realm": digest_realm}
    charm = MagicMock(spec=CharmBase)
    charm.config = config

    yield charm


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_from_charm(mocked_charm: CharmBase) -> None:
    """
    arrange: A mocked charm.
    act: Create the charmstate from the charm.
    assert: The charmstate should have the expected attributes.
    """
    test_charm_state = CharmState.from_charm(mocked_charm)

    assert test_charm_state.squid_auth_config.vault_filepath == VAULT_FILEPATH.joinpath(
        VAULT_FILENAME
    )
    assert test_charm_state.squid_auth_config.realm == DEFAULT_REALM
    assert test_charm_state.squid_auth_config.children_max == 20
    assert test_charm_state.squid_auth_config.authentication_type == AuthenticationTypeEnum.DIGEST


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_from_charm_basic() -> None:
    """
    arrange: A mocked charm with basic as authentication_type config.
    act: Create the charmstate from the charm.
    assert: The charmstate should have the expected attributes.
    """
    vault_filepath = VAULT_FILEPATH.joinpath(VAULT_FILENAME)
    config = {"vault_filepath": vault_filepath, "authentication_type": "basic"}
    charm = MagicMock(spec=CharmBase)
    charm.config = config

    test_charm_state = CharmState.from_charm(charm)

    assert test_charm_state.squid_auth_config.vault_filepath == VAULT_FILEPATH.joinpath(
        VAULT_FILENAME
    )
    assert not test_charm_state.squid_auth_config.realm
    assert test_charm_state.squid_auth_config.children_max == 20
    assert test_charm_state.squid_auth_config.authentication_type == AuthenticationTypeEnum.BASIC


@pytest.mark.parametrize(
    "nonce_garbage_interval, nonce_max_count, nonce_max_duration, realm, vault_filepath, expected",
    [
        pytest.param(
            None, 1, 1, "realm", "/abc", "nonce_garbage_interval", id="No nonce_garbage_interval"
        ),
        pytest.param(1, None, 1, "realm", "/abc", "nonce_max_count", id="No nonce_max_count"),
        pytest.param(
            1, 1, None, "realm", "/abc", "nonce_max_duration", id="No nonce_max_duration"
        ),
        pytest.param(1, 1, 1, None, "/abc", "realm", id="Realm is none"),
        pytest.param(1, 1, 1, "realm", None, "vault_filepath", id="No vault_filepath"),
    ],
)
@pytest.mark.usefixtures("tools_directory")
# pylint:disable=too-many-arguments
def test_charm_state_from_charm_missing_filepath(
    nonce_garbage_interval: int,
    nonce_max_count: int,
    nonce_max_duration: int,
    realm: str,
    vault_filepath: str,
    expected: str,
) -> None:
    """
    arrange: A mocked charm with a different set of wrong configuration values.
    act: Create the charmstate from the charm.
    assert: The expected validation exception should be raised with the expected message.
    """
    charm = MagicMock(spec=CharmBase)
    charm.config = {
        "nonce_garbage_interval": nonce_garbage_interval,
        "nonce_max_count": nonce_max_count,
        "nonce_max_duration": nonce_max_duration,
        "realm": realm,
        "vault_filepath": vault_filepath,
    }
    with pytest.raises(CharmConfigInvalidError) as exc:
        CharmState.from_charm(charm)

    assert expected in exc.value.msg


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_from_charm_digest_missing_realm() -> None:
    """
    arrange: A mocked charm with digest as authentication_type config and no realm config set.
    act: Create the charmstate from the charm.
    assert: The expected validation exception should be raised with the expected message.
    """
    charm = MagicMock(spec=CharmBase)
    charm.config = {
        "vault_filepath": "/abc",
    }
    with pytest.raises(CharmConfigInvalidError) as exc:
        CharmState.from_charm(charm)

    assert "realm configuration is mandatory for digest authentication." in exc.value.msg


def test_charm_state_from_charm_squid3_folder(
    monkeypatch: pytest.MonkeyPatch, mocked_charm: CharmBase, tmp_path: Path
) -> None:
    """
    arrange: A mocked charm with an existing squid3 folder, but non existing squid folder.
    act: Create the charmstate from the charm.
    assert: The charmstate squid_tools_path attribute should have the expected value.
    """
    squid_tools_path = Path(str(tmp_path), "tools", "squid3")
    squid_tools_path.mkdir(parents=True)

    monkeypatch.setattr(charm_state, "SQUID_TOOLS_PATH", squid_tools_path)
    monkeypatch.setattr(charm_state, "SQUID3_TOOLS_PATH", Path(str(tmp_path), "tools", "squid3"))

    test_charm_state = CharmState.from_charm(mocked_charm)

    assert test_charm_state.squid_tools_path == squid_tools_path


def test_charm_state_from_charm_no_squid_folder(mocked_charm: CharmBase) -> None:
    """
    arrange: A mocked charm with no squid folder created.
    act: Create the charmstate from the charm.
    assert: The expected exception should be raised with the expected message.
    """
    with pytest.raises(SquidPathNotFoundError) as exc:
        CharmState.from_charm(mocked_charm)

    assert exc.value.msg == "Squid tools path can't be found"


def test_charm_state_get_digest(vault_file: Path) -> None:
    """
    arrange: A charmstate with default authentication_type (digest).
    act: Get the vault from get_auth_vault method.
    assert: The vault should be an instance of HtdigestFile.
    """
    vault_file.parent.mkdir(parents=True, exist_ok=True)
    vault_file.touch()

    squid_auth_config = SquidAuthConfig(realm=DEFAULT_REALM, vault_filepath=vault_file)
    test_charm_state = CharmState(squid_auth_config=squid_auth_config, squid_tools_path="/abc")
    vault = test_charm_state.get_auth_vault()

    assert isinstance(vault, HtdigestFile)


def test_charm_state_get_basic(vault_file: Path) -> None:
    """
    arrange: A charmstate with basic as authentication_type.
    act: Get the vault from get_auth_vault method.
    assert: The vault should be an instance of HtpasswdFile.
    """
    vault_file.parent.mkdir(parents=True, exist_ok=True)
    vault_file.touch()

    squid_auth_config = SquidAuthConfig(vault_filepath=vault_file, authentication_type="basic")
    test_charm_state = CharmState(squid_auth_config=squid_auth_config, squid_tools_path="/abc")
    vault = test_charm_state.get_auth_vault()

    assert isinstance(vault, HtpasswdFile)


def test_charm_state_get_vault_no_file() -> None:
    """
    arrange: A charmstate with default authentication_type (digest) but missing vault file.
    act: Get the vault from get_auth_vault method.
    assert: The expected exception should be raised with the expected message.
    """
    squid_auth_config = SquidAuthConfig(realm=DEFAULT_REALM, vault_filepath="/abc")
    test_charm_state = CharmState(squid_auth_config=squid_auth_config, squid_tools_path="/abc")

    with pytest.raises(SquidPathNotFoundError) as exc:
        test_charm_state.get_auth_vault()

    assert VAULT_FILE_MISSING == exc.value.msg
