#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import asyncio
import logging
import uuid
from pathlib import Path

import pytest
import requests
import yaml
from pytest_operator.plugin import OpsTest
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text(encoding="utf-8"))
APP_NAME = METADATA["name"]
SQUID_CHARM = "squid-reverseproxy"
APACHE_CHARM = "apache2"


def squid_url(ops_test: OpsTest) -> str:
    """Retrieve test URL from the SQUID first unit.

    Args:
        ops_test: the current model.

    Returns:
        The URL to access the Squid proxy.
    """
    ip = ops_test.model.applications[SQUID_CHARM].units[0].public_address
    # IPv6
    if ":" in ip:
        ip = f"[{ip}]"

    return f"http://{ip}:3128"


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


@pytest.mark.skip_if_deployed
async def test_no_subordinate(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Check testing environment. Deploy Squid proxy and Apache backend.
    Set proxy relation and check access without subordinate integration.
    """
    await asyncio.gather(
        ops_test.model.deploy(SQUID_CHARM, application_name=SQUID_CHARM, series="jammy"),
        ops_test.model.deploy(APACHE_CHARM, application_name=APACHE_CHARM),
        ops_test.model.wait_for_idle(apps=[APACHE_CHARM], status="active", raise_on_blocked=True),
        ops_test.model.wait_for_idle(apps=[SQUID_CHARM], status="unknown", raise_on_blocked=True),
    )

    await asyncio.gather(
        ops_test.model.relate(f"{SQUID_CHARM}:website", f"{APACHE_CHARM}:website"),
        ops_test.model.wait_for_idle(apps=[APACHE_CHARM], status="active", raise_on_blocked=True),
        ops_test.model.wait_for_idle(apps=[SQUID_CHARM], status="unknown", raise_on_blocked=True),
    )

    assert requests.get(squid_url(ops_test), timeout=5).status_code == 200


async def test_subordinate_relation(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Relate our charm to Squid and ensure anonymous access is still ok."""
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

    assert requests.get(squid_url(ops_test), timeout=5).status_code == 200


async def test_required_auth(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Define an ACL requiring authentication and ensure anonymous users are blocked."""
    await asyncio.gather(
        ops_test.model.applications[SQUID_CHARM].set_config(
            {"auth_list": '- "!proxy_auth": [REQUIRED]\n  http_access: deny all'}
        ),
        ops_test.model.wait_for_idle(apps=[SQUID_CHARM], status="unknown", raise_on_blocked=True),
    )
    assert requests.get(squid_url(ops_test), timeout=5).status_code == 401


async def test_digest_auth(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Config Digest auth.
    Check that authenticated users have access, and that non authenticated don't.
    """
    await asyncio.gather(
        ops_test.model.applications[APP_NAME].set_config({"authentication-type": "digest"}),
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

    response = requests.get(squid_url(ops_test), auth=HTTPDigestAuth(user, password), timeout=5)
    assert response.status_code == 200

    response = requests.get(
        squid_url(ops_test), auth=HTTPDigestAuth(user, "badpassword"), timeout=5
    )
    assert response.status_code == 401


async def test_basic_auth(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Config Basic auth.
    Check that authenticated users have access, and that non authenticated don't.
    """
    await asyncio.gather(
        ops_test.model.applications[APP_NAME].set_config({"authentication-type": "basic"}),
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

    response = requests.get(squid_url(ops_test), auth=HTTPBasicAuth(user, password), timeout=5)
    assert response.status_code == 200

    response = requests.get(
        squid_url(ops_test), auth=HTTPBasicAuth(user, "badpassword"), timeout=5
    )
    assert response.status_code == 401
