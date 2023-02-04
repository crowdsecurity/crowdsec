#!/usr/bin/env python

from pytest_cs import wait_for_log, wait_for_http

import pytest

pytestmark = pytest.mark.docker


def test_no_agent(crowdsec, flavor):
    """Test DISABLE_AGENT=true"""
    env = {
        'DISABLE_AGENT': 'true',
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*CrowdSec Local API listening on 0.0.0.0:8080*")
        wait_for_http(cont, 8080, '/health')
        res = cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout
