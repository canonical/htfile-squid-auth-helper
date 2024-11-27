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
import requests
import time
import yaml
from pytest_operator.plugin import OpsTest


logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text(encoding="utf-8"))
APP_NAME = METADATA["name"]
SQUID_CHARM = "squid-reverseproxy"

PUBLIC_WEBSITE = "canonical.com"


def proxified_request_status(
    ops_test: OpsTest,
    protocol: str,
    fqdn: str,
    user: str = "",
    password: str = "",
    auth_type: str = None,
) -> int:
    """Retrieve a test URL through Squid proxy.

    Using pycurl as requests doesn't support Digest auth for proxies.

    Args:
        ops_test: the current model
        protocol: http or https
        fqdn: the website fqdn
        user: username to use for authenticated request
        password: password to use for authenticated request
        auth_type: basic or digest

    Returns:
        The HTTP status (not following redirects)
    """
    ip = ops_test.model.applications[SQUID_CHARM].units[0].public_address
    squid_url = f"http://{ip}:3128"
    target_url = f"{protocol}://{fqdn}"

    curl = pycurl.Curl()

    curl.setopt(pycurl.WRITEFUNCTION, lambda x: None)  # Hide page content

    curl.setopt(pycurl.FAILONERROR, False)  # To be able to catch 407
    # True
    # FAILED tests/integration/test_charm.py::test_authenticated_requests[True-basic-https] - AssertionError: assert 0 in [407]
    # FAILED tests/integration/test_charm.py::test_authenticated_requests[True-digest-https] - AssertionError: assert 0 in [407]
    # False
    # FAILED tests/integration/test_charm.py::test_authenticated_requests[True-basic-https] - AssertionError: assert 0 in [407]
    # FAILED tests/integration/test_charm.py::test_authenticated_requests[True-digest-https] - AssertionError: assert 0 in [407]
    # ERROR    integration.test_charm:test_charm.py:83 Curl error: (56, 'Received HTTP code 407 from proxy after CONNECT') 0 0

    curl.setopt(pycurl.URL, target_url)
    curl.setopt(pycurl.PROXY, squid_url)
    curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_HTTP)

    if auth_type == "basic":
        curl.setopt(pycurl.PROXYAUTH, pycurl.HTTPAUTH_BASIC)
    elif auth_type == "digest":
        curl.setopt(pycurl.PROXYAUTH, pycurl.HTTPAUTH_DIGEST)

    if user:
        curl.setopt(pycurl.PROXYUSERPWD, f"{user}:{password}")

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
    """Deploy the charm alone."""
    # Deploy the charm and wait for active/idle status
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
async def test_default_squid_setup(ops_test: OpsTest):
    """Check testing environment. Deploy Squid and check that we can access public websites."""
    await asyncio.gather(
        ops_test.model.deploy(
            SQUID_CHARM,
            application_name=SQUID_CHARM,
            series="jammy",
            config={
                "wait_for_auth_helper": False,
                "port_options": "",
                "auth_list": "[{'src': ['127.0.0.1']}]",
            },
        ),
        ops_test.model.wait_for_idle(apps=[SQUID_CHARM], status="unknown", raise_on_blocked=True),
    )
    time.sleep(2)
    assert proxified_request_status(ops_test, "http", PUBLIC_WEBSITE) in [200, 301]


@pytest.mark.skip_if_deployed
async def test_relation(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Define an ACL requiring authentication and ensure anonymous users are blocked."""
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

    await asyncio.gather(
        ops_test.model.applications[SQUID_CHARM].set_config(
            {"auth_list": '- "proxy_auth": [REQUIRED]'}
        ),
        ops_test.model.wait_for_idle(apps=[SQUID_CHARM], status="unknown", raise_on_blocked=True),
    )

    assert (
        proxified_request_status(ops_test, "http", PUBLIC_WEBSITE) == 407
    )  #  Proxy Authentication Required


@pytest.mark.parametrize("protocol", ["http", "https"])
@pytest.mark.parametrize("auth_type", ["basic", "digest"])
async def test_authenticated_requests(
    ops_test: OpsTest,
    auth_type: str,
    protocol: str,
):
    """Config Basic auth.
    Check that authenticated users have access, and that non authenticated don't.
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
        ops_test, protocol, PUBLIC_WEBSITE, user, password, auth_type=auth_type
    ) in [200, 301]


@pytest.mark.parametrize("auth_type", ["basic", "digest"])
async def test_unauthenticated_requests(
    ops_test: OpsTest,
    auth_type: str,
):
    """Config Basic auth.
    Check that authenticated users have access, and that non authenticated don't.
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

    assert (
        proxified_request_status(
            ops_test, "http", PUBLIC_WEBSITE, user, "badpassword", auth_type=auth_type
        )
        == 407
    )

    assert (
        proxified_request_status(
            ops_test, "http", PUBLIC_WEBSITE, "baduser", password, auth_type=auth_type
        )
        == 407
    )
