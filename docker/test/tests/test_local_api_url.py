#!/usr/bin/env python

from http import HTTPStatus

import pytest

pytestmark = pytest.mark.docker


def test_local_api_url_default(crowdsec, flavor):
    """Test LOCAL_API_URL (default)"""
    with crowdsec(flavor=flavor) as cs:
        cs.wait_for_log([
            "*CrowdSec Local API listening on *:8080*",
            "*Starting processing data*"
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "on http://0.0.0.0:8080/" in stdout
        assert "You can successfully interact with Local API (LAPI)" in stdout


def test_local_api_url(crowdsec, flavor):
    """Test LOCAL_API_URL (custom)"""
    env = {
        "LOCAL_API_URL": "http://127.0.0.1:8080"
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log([
            "*CrowdSec Local API listening on *:8080*",
            "*Starting processing data*"
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "on http://127.0.0.1:8080/" in stdout
        assert "You can successfully interact with Local API (LAPI)" in stdout


def test_local_api_url_ipv6(crowdsec, flavor):
    """Test LOCAL_API_URL (custom with ipv6)"""
    pytest.skip("ipv6 not supported yet")

    # how to configure docker with ipv6 in a custom network?
    # FIXME: https://forums.docker.com/t/assigning-default-ipv6-addresses/128665/3
    # FIXME: https://github.com/moby/moby/issues/41438

    env = {
        "LOCAL_API_URL": "http://[::1]:8080"
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log([
            "*Starting processing data*",
            "*CrowdSec Local API listening on [::1]:8080*",
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "on http://[::1]:8080/" in stdout
        assert "You can successfully interact with Local API (LAPI)" in stdout
