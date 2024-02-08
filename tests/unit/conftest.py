# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""pytest fixtures for the unit test."""

# pylint: disable=too-few-public-methods, protected-access


import typing
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from unit.constants import DIGEST_FILENAME, DIGEST_FILEPATH

import charm_state


@pytest.fixture(name="tools_directory")
def tools_directory_fixture(monkeypatch: pytest.MonkeyPatch) -> typing.Generator[None, None, None]:
    """Fixture used to use a temp directory for squid tools folder."""
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()

    squid_tools_path = Path(tmp_digest_dir.name, "tools", "squid")
    squid_tools_path.mkdir(parents=True)

    monkeypatch.setattr(charm_state, "SQUID_TOOLS_PATH", squid_tools_path)
    monkeypatch.setattr(
        charm_state, "SQUID3_TOOLS_PATH", Path(tmp_digest_dir.name, "tools", "squid3")
    )

    yield

    tmp_digest_dir.cleanup()


@pytest.fixture(name="digest_file")
def digest_file_fixture() -> typing.Generator[Path, None, None]:
    """Fixture used to use a temp directory for digest file."""
    # pylint: disable=consider-using-with
    tmp_digest_dir = TemporaryDirectory()

    yield Path(tmp_digest_dir.name, DIGEST_FILEPATH, DIGEST_FILENAME)

    tmp_digest_dir.cleanup()
