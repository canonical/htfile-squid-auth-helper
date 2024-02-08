# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more about testing at: https://juju.is/docs/sdk/testing

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
"""Unit tests."""


from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Generator
from unittest.mock import MagicMock

import pytest
from ops import CharmBase
from passlib.apache import HtdigestFile
from unit.constants import DEFAULT_REALM, DIGEST_FILENAME, DIGEST_FILEPATH

import charm_state
from charm_state import HTDIGEST_FILE_MISSING, CharmState, DigestAuthConfig
from exceptions import CharmConfigInvalidError, SquidPathNotFoundError


@pytest.fixture(name="mocked_charm")
def mocked_charm_fixture() -> Generator[CharmBase, None, None]:
    digest_filepath = DIGEST_FILEPATH.joinpath(DIGEST_FILENAME)
    digest_realm = DEFAULT_REALM
    config = {"digest_filepath": digest_filepath, "realm": digest_realm}
    charm = MagicMock(spec=CharmBase)
    charm.config = config

    yield charm


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_from_charm(mocked_charm: CharmBase) -> None:
    test_charm_state = CharmState.from_charm(mocked_charm)

    assert test_charm_state.digest_auth_config.digest_filepath == DIGEST_FILEPATH.joinpath(
        DIGEST_FILENAME
    )
    assert test_charm_state.digest_auth_config.realm == DEFAULT_REALM
    assert test_charm_state.digest_auth_config.children_max == 20


@pytest.mark.usefixtures("tools_directory")
def test_charm_state_from_charm_invalid_data() -> None:
    charm = MagicMock(spec=CharmBase)
    charm.config = {}
    with pytest.raises(CharmConfigInvalidError) as exc:
        CharmState.from_charm(charm)

    assert "realm" in str(exc.value.msg)
    assert "digest_filepath" in str(exc.value.msg)


def test_charm_state_from_charm_squid3_folder(
    monkeypatch: pytest.MonkeyPatch, mocked_charm: CharmBase
) -> None:
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()

    squid_tools_path = Path(tmp_digest_dir.name, "tools", "squid3")
    squid_tools_path.mkdir(parents=True)

    monkeypatch.setattr(charm_state, "SQUID_TOOLS_PATH", squid_tools_path)
    monkeypatch.setattr(
        charm_state, "SQUID3_TOOLS_PATH", Path(tmp_digest_dir.name, "tools", "squid3")
    )

    test_charm_state = CharmState.from_charm(mocked_charm)

    assert test_charm_state.squid_tools_path == squid_tools_path

    tmp_digest_dir.cleanup()


def test_charm_state_from_charm_no_squid_folder(mocked_charm: CharmBase) -> None:
    with pytest.raises(SquidPathNotFoundError) as exc:
        CharmState.from_charm(mocked_charm)

    assert exc.value.msg == "Squid tools path can't be found"


def test_charm_state_get_digest(digest_file: Path) -> None:
    digest_file.parent.mkdir(parents=True)
    digest_file.touch()

    digest_auth_config = DigestAuthConfig(realm=DEFAULT_REALM, digest_filepath=digest_file)
    test_charm_state = CharmState(digest_auth_config=digest_auth_config, squid_tools_path="/abc")
    digest = test_charm_state.get_digest()

    assert isinstance(digest, HtdigestFile)


def test_charm_state_get_digest_no_file() -> None:
    digest_auth_config = DigestAuthConfig(realm=DEFAULT_REALM, digest_filepath="/abc")
    test_charm_state = CharmState(digest_auth_config=digest_auth_config, squid_tools_path="/abc")

    with pytest.raises(SquidPathNotFoundError) as exc:
        test_charm_state.get_digest()

    assert HTDIGEST_FILE_MISSING == exc.value.msg
