# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""State of the Charm."""

import dataclasses
import functools
import itertools
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from ops import CharmBase, EventBase
from passlib.apache import HtdigestFile, HtpasswdFile
from pydantic import BaseModel, ValidationError

from exceptions import CharmConfigInvalidError, SquidPathNotFoundError

VAULT_FILE_MISSING = "Vault file is missing, something probably went wrong during install."

SQUID_TOOLS_PATH = Path("/usr/lib/squid")
SQUID3_TOOLS_PATH = Path("/usr/lib/squid3")

SQUID_DIGEST_AUTH_PROGRAM = "digest_file_auth"
SQUID_BASIC_AUTH_PROGRAM = "basic_ncsa_auth"


class AuthenticationTypeEnum(str, Enum):
    """Represent the authentication type supported.

    Attributes:
        BASIC: Basic authentication in htpasswd file.
        DIGEST: Digest authentication in htdigest file.
    """

    BASIC = "basic"
    DIGEST = "digest"


class SquidAuthConfig(BaseModel):
    """Represent the Htfile Auth helper configuration values.

    Attributes:
        children_max: children_max config.
        children_startup: children_startup config.
        children_idle: children_idle config.
        vault_filepath: vault_filepath config.
        nonce_garbage_interval: nonce_garbage_interval config.
        nonce_max_duration: nonce_max_duration config.
        nonce_max_count: nonce_max_count config.
        realm: realm config.
        authentication_type: One of digest or basic AuthenticationTypeEnum.
    """

    children_max: int = 20
    children_startup: int = 0
    children_idle: int = 1
    vault_filepath: Path
    nonce_garbage_interval: int = 5
    nonce_max_duration: int = 30
    nonce_max_count: int = 50
    realm: str = ""
    authentication_type: AuthenticationTypeEnum = AuthenticationTypeEnum.DIGEST


@dataclasses.dataclass(frozen=True)
class CharmState:
    """State of the Charm.

    Attributes:
        squid_auth_config: An instance of SquidAuthConfig.
        squid_tools_path: A validated path for Squid tools folder.
    """

    squid_auth_config: SquidAuthConfig
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
            validated_charm_config = SquidAuthConfig(**dict(charm.config.items()))  # type: ignore
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise CharmConfigInvalidError(f"invalid configuration: {error_field_str}") from exc

        squid_tools_path = _get_squid_tools_path()

        if (
            not validated_charm_config.realm
            and validated_charm_config.authentication_type == AuthenticationTypeEnum.DIGEST
        ):
            raise CharmConfigInvalidError(
                ("realm configuration is mandatory for digest authentication.")
            )

        return cls(
            squid_auth_config=validated_charm_config,
            squid_tools_path=squid_tools_path,
        )

    def vault_file_exists(self) -> bool:
        """Check if the vault file exists.

        Returns: Whether the vault file exists.
        """
        return self.squid_auth_config.vault_filepath.exists()

    def get_auth_vault(self) -> HtdigestFile | HtpasswdFile:
        """Load the vault file in an HtdigestFile or HtpasswdFile instance.

        Returns: An instance of HtdigestFile or HtpasswdFile.

        Raises:
            SquidPathNotFoundError: If the digest file is missing.
        """
        if not self.vault_file_exists():
            raise SquidPathNotFoundError(VAULT_FILE_MISSING)

        return (
            HtdigestFile(
                self.squid_auth_config.vault_filepath, default_realm=self.squid_auth_config.realm
            )
            if self.squid_auth_config.authentication_type == AuthenticationTypeEnum.DIGEST
            else HtpasswdFile(self.squid_auth_config.vault_filepath, "sha256_crypt")
        )

    def get_as_relation_data(self) -> list[dict[str, Any]]:
        """Format the CharmState data as a dictionary for relation data.

        Returns: A dictionary with CharmState data.
        """
        config = self.squid_auth_config
        children = (
            f"{config.children_max} startup={config.children_startup} idle={config.children_idle}"
        )
        relation_data: dict[str, str | int] = {
            "scheme": str(config.authentication_type),
            "program": self._get_squid_authentication_program(),
            "children": children,
        }
        if config.authentication_type == AuthenticationTypeEnum.DIGEST:
            relation_data.update(
                {
                    "realm": config.realm,
                    "nonce_garbage_interval": f"{config.nonce_garbage_interval} minutes",
                    "nonce_max_duration": f"{config.nonce_max_duration} minutes",
                    "nonce_max_count": config.nonce_max_count,
                }
            )

        return [relation_data]

    def _get_squid_authentication_program(self) -> str:
        """Build the program parameter for Squid configuration.

        Returns: The excepted command line depending on the authentication_type
        """
        program = f"{self.squid_tools_path}/"
        return (
            f"{program}{str(SQUID_DIGEST_AUTH_PROGRAM)} -c {self.squid_auth_config.vault_filepath}"
            if self.squid_auth_config.authentication_type == AuthenticationTypeEnum.DIGEST
            else f"{program}{str(SQUID_BASIC_AUTH_PROGRAM)} {self.squid_auth_config.vault_filepath}"
        )


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
