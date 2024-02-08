# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""State of the Charm."""

import dataclasses
import functools
import itertools
from pathlib import Path
from typing import Any, Callable

from ops import CharmBase, EventBase
from passlib.apache import HtdigestFile
from pydantic import BaseModel, Field, ValidationError

from exceptions import CharmConfigInvalidError, SquidPathNotFoundError

HTDIGEST_FILE_MISSING = "Htdigest file is missing, something probably went wrong during install."

SQUID_TOOLS_PATH = Path("/usr/lib/squid")
SQUID3_TOOLS_PATH = Path("/usr/lib/squid3")


class DigestAuthConfig(BaseModel):
    """Represent the Digest Auth helper configuration values.

    Attributes:
        children_max: children_max config.
        children_startup: children_startup config.
        children_idle: children_idle config.
        digest_filepath: digest_filepath config.
        nonce_garbage_interval: nonce_garbage_interval config.
        nonce_max_duration: nonce_max_duration config.
        nonce_max_count: nonce_max_count config.
        realm: realm config.
    """

    children_max: int = 20
    children_startup: int = 0
    children_idle: int = 1
    digest_filepath: Path
    nonce_garbage_interval: int = 5
    nonce_max_duration: int = 30
    nonce_max_count: int = 50
    realm: str = Field(..., min_length=2)


@dataclasses.dataclass(frozen=True)
class CharmState:
    """State of the Charm.

    Attributes:
        digest_auth_config: An instance of DigestAuthConfig.
        squid_tools_path: A validated path for Squid tools folder.
    """

    digest_auth_config: DigestAuthConfig
    squid_tools_path: Path

    @classmethod
    def from_charm(cls, charm: CharmBase) -> "CharmState":
        """Initialize a new instance of the CharmState class from the associated charm.

        Args:
            charm: The charm instance associated with this state.

        Returns: An instance of the CharmState object.

        Raises:
            CharmConfigInvalidError: For any validation error in the charm config data.
        """
        try:
            # Ignores type error because of the dictionary
            validated_charm_config = DigestAuthConfig(**dict(charm.config.items()))  # type: ignore
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise CharmConfigInvalidError(f"invalid configuration: {error_field_str}") from exc

        squid_tools_path = _get_squid_tools_path()

        return cls(digest_auth_config=validated_charm_config, squid_tools_path=squid_tools_path)

    def digest_file_exists(self) -> bool:
        """Check if the digest file exists.

        Returns: Whether the digest file exists.
        """
        return self.digest_auth_config.digest_filepath.exists()

    def get_digest(self) -> HtdigestFile:
        """Load the digest file in an HtdigestFile instance.

        Returns: An instance of HtdigestFile.

        Raises:
            SquidPathNotFoundError: If the digest file is missing.
        """
        if not self.digest_file_exists():
            raise SquidPathNotFoundError(HTDIGEST_FILE_MISSING)

        return HtdigestFile(
            self.digest_auth_config.digest_filepath, default_realm=self.digest_auth_config.realm
        )

    def get_as_relation_data(self) -> list[dict[str, Any]]:
        """Format the CharmState data as a dictionary for relation data.

        Returns: A dictionary with CharmState data.
        """
        config = self.digest_auth_config
        children = (
            f"{config.children_max} startup={config.children_startup} idle={config.children_idle}"
        )
        return [
            {
                "scheme": "digest",
                "program": f"{self.squid_tools_path}/digest_file_auth -c {config.digest_filepath}",
                "children": children,
                "realm": config.realm,
                "nonce_garbage_interval": f"{config.nonce_garbage_interval} minutes",
                "nonce_max_duration": f"{config.nonce_max_duration} minutes",
                "nonce_max_count": config.nonce_max_count,
            }
        ]


def _get_squid_tools_path() -> Path:
    """Define config and tools folders of squid.

    Returns: A validated path for Squid tools.

    Raises:
        SquidPathNotFoundError: If the tools folder can't be found.
    """
    if not SQUID_TOOLS_PATH.exists() and not SQUID3_TOOLS_PATH.exists():
        raise SquidPathNotFoundError("Squid tools path can't be found")

    return SQUID_TOOLS_PATH if SQUID_TOOLS_PATH.exists() else SQUID3_TOOLS_PATH


def inject(
    func: Callable[[CharmBase, EventBase], Any]
) -> Callable[..., Callable[[CharmBase, EventBase], Any]]:
    """Create a decorator that injects the charm_state into the charm instance.

    Args:
        func: The method to wrap.

    Returns: A wrapper method.
    """

    @functools.wraps(func)
    def wrapper(charm: CharmBase, event: EventBase) -> Any:
        """Instantiate and inject the CharmState before the hook is executed.

        Args:
            charm: The Charm instance.
            event: The event for that hook.

        Returns: The outcome of the wrapped hook method
        """
        attribute_name = "_charm_state"

        setattr(charm, attribute_name, CharmState.from_charm(charm))

        try:
            result = func(charm, event)
        finally:
            setattr(charm, attribute_name, None)

        return result

    return wrapper
