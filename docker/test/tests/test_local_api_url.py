#!/usr/bin/env python

from pytest_cs import wait_for_log, wait_for_http

import pytest

pytestmark = pytest.mark.docker


def test_local_api_url_default(crowdsec, flavor):
    """Test LOCAL_API_URL (default)"""
    with crowdsec(flavor=flavor) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health')
        res = cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "on http://0.0.0.0:8080/" in stdout
        assert "You can successfully interact with Local API (LAPI)" in stdout
        logs = cont.logs().decode().splitlines()
        assert any("CrowdSec Local API listening on 0.0.0.0:8080" in line for line in logs)


def test_local_api_url(crowdsec, flavor):
    """Test LOCAL_API_URL (custom)"""
    env = {
        "LOCAL_API_URL": "http://127.0.0.1:8080"
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health')
        res = cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "on http://127.0.0.1:8080/" in stdout
        assert "You can successfully interact with Local API (LAPI)" in stdout
        logs = cont.logs().decode().splitlines()
        # still listen on all interfaces
        assert any("CrowdSec Local API listening on 0.0.0.0:8080" in line for line in logs)


def test_local_api_url_ipv6(crowdsec, flavor):
    """Test LOCAL_API_URL (custom with ipv6)"""
    pytest.skip("ipv6 not supported yet")

    # how to configure docker with ipv6 in a custom network?
    # FIXME: https://forums.docker.com/t/assigning-default-ipv6-addresses/128665/3
    # FIXME: https://github.com/moby/moby/issues/41438

    env = {
        "LOCAL_API_URL": "http://[::1]:8080"
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health')
        res = cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "on http://[::1]:8080/" in stdout
        assert "You can successfully interact with Local API (LAPI)" in stdout
        logs = cont.logs().decode().splitlines()
        # still listen on all interfaces
        assert any("CrowdSec Local API listening on 0.0.0.0:8080" in line for line in logs)
