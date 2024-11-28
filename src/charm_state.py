# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""State of the Charm."""

import dataclasses
import itertools
from enum import Enum
from pathlib import Path

from ops import CharmBase
from pydantic import BaseModel, ValidationError

from exceptions import CharmConfigInvalidError, SquidPathNotFoundError

SQUID_TOOLS_PATH = Path("/usr/lib/squid")

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
            SquidPathNotFoundError: If none of the squid tools path exists.
        """
        mapped_config = {
            field: charm.config[field.replace("_", "-")]
            for field in SquidAuthConfig.model_fields
            if field.replace("_", "-") in charm.config
        }

        try:
            validated_charm_config = SquidAuthConfig.model_validate(mapped_config)
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise CharmConfigInvalidError(f"invalid configuration: {error_field_str}") from exc

        if not SQUID_TOOLS_PATH.exists():
            raise SquidPathNotFoundError("Squid tools path can't be found")

        if (
            not validated_charm_config.realm
            and validated_charm_config.authentication_type == AuthenticationTypeEnum.DIGEST
        ):
            raise CharmConfigInvalidError(
                ("realm configuration is mandatory for digest authentication.")
            )

        return cls(
            squid_auth_config=validated_charm_config,
            squid_tools_path=SQUID_TOOLS_PATH,
        )

    def vault_file_exists(self) -> bool:
        """Check if the vault file exists.

        Returns: Whether the vault file exists.
        """
        return self.squid_auth_config.vault_filepath.exists()

    def get_squid_authentication_program(self) -> str:
        """Build the program parameter for Squid configuration.

        Returns: The excepted command line depending on the authentication_type
        """
        program = f"{self.squid_tools_path}/"
        return (
            f"{program}{SQUID_DIGEST_AUTH_PROGRAM} -c {self.squid_auth_config.vault_filepath}"
            if self.squid_auth_config.authentication_type == AuthenticationTypeEnum.DIGEST
            else f"{program}{SQUID_BASIC_AUTH_PROGRAM} {self.squid_auth_config.vault_filepath}"
        )
