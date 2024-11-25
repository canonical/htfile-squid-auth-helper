#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import asyncio
import logging
from pathlib import Path

import pytest
import requests
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text(encoding="utf-8"))
APP_NAME = METADATA["name"]
PRINCIPAL_CHARM = "squid-reverseproxy"
WEBSITE_CHARM = "apache2"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, pytestconfig: pytest.Config):
    """Deploy the charm together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    # Deploy the charm and wait for active/idle status
    charm = pytestconfig.getoption("--charm-file")
    if not charm:
        charm = await ops_test.build_charm(".")

    assert ops_test.model

    logger.info("Deploying subordinate charm alone")
    await asyncio.gather(
        ops_test.model.deploy(
            f"./{charm}", application_name=APP_NAME, num_units=0, series="jammy"
        ),
        ops_test.model.wait_for_idle(
            apps=[APP_NAME], status="unknown", wait_for_units=0, raise_on_blocked=True, timeout=60
        ),
    )

    logger.info("Deploying %s and %s", PRINCIPAL_CHARM, WEBSITE_CHARM)
    await asyncio.gather(
        ops_test.model.deploy(PRINCIPAL_CHARM, application_name=PRINCIPAL_CHARM, series="jammy"),
        ops_test.model.deploy(WEBSITE_CHARM, application_name=WEBSITE_CHARM),
        ops_test.model.wait_for_idle(apps=[WEBSITE_CHARM], status="active", raise_on_blocked=True),
        ops_test.model.wait_for_idle(
            apps=[PRINCIPAL_CHARM], status="unknown", raise_on_blocked=True
        ),
    )

    logger.info("Validating initial setup")
    ip = ops_test.model.applications[PRINCIPAL_CHARM].units[0].public_address
    url = f"http://{ip}:3128"
    assert requests.get(url, timeout=5).status_code == 403

    logger.info("Setting up %s as a proxy to %s", PRINCIPAL_CHARM, WEBSITE_CHARM)
    await asyncio.gather(
        ops_test.model.relate(f"{PRINCIPAL_CHARM}:website", f"{WEBSITE_CHARM}:website"),
        ops_test.model.wait_for_idle(apps=[WEBSITE_CHARM], status="active", raise_on_blocked=True),
        ops_test.model.wait_for_idle(
            apps=[PRINCIPAL_CHARM], status="unknown", raise_on_blocked=True
        ),
    )

    logger.info("Validating proxy setup")
    assert requests.get(url, timeout=5).status_code == 200

    logger.info("Enable local auth through our subordinate")
    await asyncio.gather(
        await ops_test.model.relate(APP_NAME, PRINCIPAL_CHARM),
        ops_test.model.wait_for_idle(
            apps=[APP_NAME, PRINCIPAL_CHARM],
            status="active",
            wait_for_units=0,
            raise_on_blocked=True,
        ),
    )

    logger.info("Setting up ACL and validating it")
    await asyncio.gather(
        ops_test.model.applications[PRINCIPAL_CHARM].set_config(
            {"auth_list": '- "!proxy_auth": [REQUIRED]\n  http_access: deny all'}
        ),
        ops_test.model.wait_for_idle(
            apps=[PRINCIPAL_CHARM], status="unknown", raise_on_blocked=True
        ),
    )
    assert requests.get(url, timeout=5).status_code == 401
