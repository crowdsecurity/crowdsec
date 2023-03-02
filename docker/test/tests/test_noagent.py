#!/usr/bin/env python

from http import HTTPStatus

import pytest

pytestmark = pytest.mark.docker


def test_no_agent(crowdsec, flavor):
    """Test DISABLE_AGENT=true"""
    env = {
        'DISABLE_AGENT': 'true',
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*CrowdSec Local API listening on 0.0.0.0:8080*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout
