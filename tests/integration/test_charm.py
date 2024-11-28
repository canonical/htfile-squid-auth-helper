#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import asyncio
import logging
import uuid
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

from charm import SQUID_USER
from tests.unit.constants import VAULT_FILENAME, VAULT_FILEPATH

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text(encoding="utf-8"))
APP_NAME = METADATA["name"]
CLIENT_NAME = "client"

SQUID_CHARM = "squid-reverseproxy"

FQDN = "canonical.com"


async def check_access(
    ops_test: OpsTest,
    protocol: str,
    fqdn: str,
    credentials: str = "",
    auth_type: str = "",
) -> int:
    """Retrieve a test URL from a client through Squid proxy.

    Args:
        ops_test: the current model
        protocol: http or https
        fqdn: the website fqdn
        credentials: 'username:password' to use for authenticated request
        auth_type: basic or digest

    Returns:
        The HTTP status (not following redirects)
    """
    assert ops_test.model

    squid_ip = ops_test.model.applications[SQUID_CHARM].units[0].public_address
    squid_url = f"http://{squid_ip}:3128"

    target_url = f"{protocol}://{fqdn}"

    auth_options = ""
    if auth_type == "basic":
        auth_options = "--proxy-basic"
    elif auth_type == "digest":
        auth_options = "--proxy-digest"

    if credentials:
        auth_options += f" --proxy-user {credentials}"

    command = "curl -o /dev/null -s -w '%{http_code}' "  # Only returns status code
    command += "--no-location --connect-timeout 2 --max-time 2 "  # Don't follow redirects
    command += f"--proxy {squid_url} {auth_options} {target_url}"

    res = await ops_test.model.applications[CLIENT_NAME].units[0].ssh(command)

    return int(res)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Deploy the charm alone, and wait for 'unknown' status."""
    charm = pytestconfig.getoption("--charm-file")
    if not charm:
        charm = await ops_test.build_charm(".")

    assert ops_test.model

    await asyncio.gather(
        ops_test.model.deploy(
            f"./{charm}", application_name=APP_NAME, num_units=0, series="jammy"
        ),
        ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="unknown",
            wait_for_exact_units=0,
            raise_on_blocked=True,
            timeout=60,
        ),
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_squid_and_client(ops_test: OpsTest):
    """Check testing environment.

    Deploy Squid and check that it waits for an auth helper.
    Deploy a client unit to be able to test access later.
    """
    assert ops_test.model

    await asyncio.gather(
        ops_test.model.deploy(
            SQUID_CHARM,
            application_name=SQUID_CHARM,
            series="jammy",
            config={
                "wait_for_auth_helper": True,
                "port_options": "",
                "auth_list": '- "proxy_auth": [REQUIRED]',
            },
        ),
        ops_test.model.wait_for_idle(apps=[SQUID_CHARM], status="unknown", raise_on_blocked=True),
        ops_test.model.deploy(
            "ubuntu",
            application_name=CLIENT_NAME,
            series="jammy",
        ),
        ops_test.model.wait_for_idle(apps=[CLIENT_NAME], status="active", raise_on_blocked=True),
    )
    open_ports = await ops_test.model.applications[SQUID_CHARM].units[0].ssh("ss -ntl")

    # Ensure Squid is waiting for auth provider before starting
    assert ":3128" not in open_ports


@pytest.mark.skip_if_deployed
async def test_relation(ops_test: OpsTest):
    """Integrate the auth helper and sure Squid has started with authentication required."""
    assert ops_test.model

    await asyncio.gather(
        ops_test.model.relate(APP_NAME, SQUID_CHARM),
        ops_test.model.wait_for_idle(
            apps=[SQUID_CHARM],
            status="unknown",
        ),
        ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
        ),
    )

    assert await check_access(ops_test, "http", FQDN) == 407  # Proxy Authentication Required


@pytest.mark.abort_on_fail
async def test_vault_ownership_and_permissions(ops_test: OpsTest):
    """Check vault ownership and permissions."""
    assert ops_test.model

    vault_perms = await (
        ops_test.model.applications[SQUID_CHARM]
        .units[0]
        .ssh(f"sudo find /{VAULT_FILEPATH} -maxdepth 0 -printf '%u %g %m'")
    )
    assert vault_perms == f"{SQUID_USER} root 700"

    vault_parent_perms = await (
        ops_test.model.applications[SQUID_CHARM]
        .units[0]
        .ssh(f"sudo find /{VAULT_FILEPATH}/{VAULT_FILENAME} -printf '%u %g %m'")
    )
    assert vault_parent_perms == f"{SQUID_USER} root 600"


@pytest.mark.parametrize("protocol", ["http", "https"])
@pytest.mark.parametrize("auth_type", ["basic", "digest"])
async def test_authenticated_requests(
    ops_test: OpsTest,
    auth_type: str,
    protocol: str,
):
    """Check that authenticated users have access.

    Test Basic and Digest protocols for http and https websites.
    """
    assert ops_test.model

    await asyncio.gather(
        ops_test.model.applications[APP_NAME].set_config({"authentication-type": auth_type}),
        ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", raise_on_blocked=True),
    )

    user = str(uuid.uuid4())
    action = (
        await ops_test.model.applications[APP_NAME]
        .units[0]
        .run_action("create-user", username=user)
    )
    await action.wait()
    assert action.status == "completed"

    password = action.results["password"]
    assert password

    assert await check_access(
        ops_test, protocol, FQDN, f"{user}:{password}", auth_type=auth_type
    ) in [200, 301]


@pytest.mark.parametrize("auth_type", ["basic", "digest"])
async def test_unauthenticated_requests(
    ops_test: OpsTest,
    auth_type: str,
):
    """Check that unauthenticated users cannot access."""
    assert ops_test.model

    await asyncio.gather(
        ops_test.model.applications[APP_NAME].set_config({"authentication-type": auth_type}),
        ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", raise_on_blocked=True),
    )

    user = str(uuid.uuid4())
    action = (
        await ops_test.model.applications[APP_NAME]
        .units[0]
        .run_action("create-user", username=user)
    )
    await action.wait()
    assert action.status == "completed"

    password = action.results["password"]
    assert password

    creds = f"{user}:badpass"
    assert await check_access(ops_test, "http", FQDN, creds, auth_type=auth_type) == 407

    creds = f"baduser:{password}"
    assert await check_access(ops_test, "http", FQDN, creds, auth_type=auth_type) == 407
