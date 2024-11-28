# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""pytest fixtures for the unit test."""

# pylint: disable=too-few-public-methods, protected-access


import typing
from pathlib import Path

import pytest
from unit.constants import VAULT_FILENAME, VAULT_FILEPATH

import charm_state


@pytest.fixture(name="tools_directory")
def tools_directory_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> typing.Generator[None, None, None]:
    """Fixture used to use a temp directory for squid tools folder."""
    squid_tools_path = Path(str(tmp_path), "tools", "squid")
    squid_tools_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(charm_state, "SQUID_TOOLS_PATH", squid_tools_path)

    yield


@pytest.fixture(name="vault_file")
def vault_file_fixture(tmp_path: Path) -> typing.Generator[Path, None, None]:
    """Fixture used to use a temp directory for vault file."""
    yield Path(str(tmp_path), VAULT_FILEPATH, VAULT_FILENAME)
