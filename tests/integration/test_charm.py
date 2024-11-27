#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import asyncio
import logging
import uuid
from pathlib import Path

import pycurl
import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text(encoding="utf-8"))
APP_NAME = METADATA["name"]
SQUID_CHARM = "squid-reverseproxy"

FQDN = "canonical.com"


def proxified_request_status(
    ops_test: OpsTest,
    protocol: str,
    fqdn: str,
    credentials: str = "",
    auth_type: str = "",
) -> int:
    """Retrieve a test URL through Squid proxy.

    Using pycurl as requests doesn't support Digest auth for proxies.

    Args:
        ops_test: the current model
        protocol: http or https
        fqdn: the website fqdn
        credentials: 'username:password' to use for authenticated request
        auth_type: basic or digest

    Returns:
        The HTTP status (not following redirects)
    """
    ip = ops_test.model.applications[SQUID_CHARM].units[0].public_address
    squid_url = f"http://{ip}:3128"
    target_url = f"{protocol}://{fqdn}"

    curl = pycurl.Curl()

    curl.setopt(pycurl.WRITEFUNCTION, lambda x: None)  # Hide page content from tests output

    curl.setopt(pycurl.URL, target_url)
    curl.setopt(pycurl.PROXY, squid_url)
    curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_HTTP)

    if auth_type == "basic":
        curl.setopt(pycurl.PROXYAUTH, pycurl.HTTPAUTH_BASIC)
    elif auth_type == "digest":
        curl.setopt(pycurl.PROXYAUTH, pycurl.HTTPAUTH_DIGEST)

    if credentials:
        curl.setopt(pycurl.PROXYUSERPWD, credentials)

    curl.setopt(pycurl.SSL_VERIFYPEER, False)

    curl.setopt(pycurl.TIMEOUT, 5)
    try:
        curl.perform()
    except pycurl.error as e:
        logger.error(f"Curl error: {e}")

    return curl.getinfo(pycurl.RESPONSE_CODE)


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
            apps=[APP_NAME], status="unknown", wait_for_units=0, raise_on_blocked=True, timeout=60
        ),
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_squid(ops_test: OpsTest):
    """Check testing environment.
    Deploy Squid and check that it waits for an auth helper.
    """
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
    )

    open_ports = ops_test.model.applications[APP_NAME].units[0].ssh("ss -ntl")
    assert ":3128" not in open_ports


@pytest.mark.skip_if_deployed
async def test_relation(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Integrate the auth helper and sure Squid has started with authentication required."""
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

    assert proxified_request_status(ops_test, "http", FQDN) == 407  # Proxy Authentication Required


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

    assert proxified_request_status(
        ops_test, protocol, FQDN, f"{user}:{password}", auth_type=auth_type
    ) in [200, 301]


@pytest.mark.parametrize("auth_type", ["basic", "digest"])
async def test_unauthenticated_requests(
    ops_test: OpsTest,
    auth_type: str,
):
    """Check that unauthenticated users cannot access."""
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
    assert proxified_request_status(ops_test, "http", FQDN, creds, auth_type=auth_type) == 407

    creds = f"baduser:{password}"
    assert proxified_request_status(ops_test, "http", FQDN, creds, auth_type=auth_type) == 407
