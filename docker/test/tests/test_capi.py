#!/usr/bin/env python

from http import HTTPStatus

import pytest
pytestmark = pytest.mark.docker


def test_no_capi(crowdsec, flavor):
    """Test no CAPI (disabled by default in tests)"""

    env = {
        'DISABLE_ONLINE_API': 'true',
    }

    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli capi status')
        assert res.exit_code == 1
        assert "You can successfully interact with Central API (CAPI)" not in res.output.decode()

        logs = cs.log_lines()
        assert not any("Successfully registered to Central API (CAPI)" in line for line in logs)
        assert not any("Registration to online API done" in line for line in logs)


def test_capi(crowdsec, flavor):
    """Test CAPI"""

    env = {
        'DISABLE_ONLINE_API': 'false',
    }

    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli capi status')
        assert res.exit_code == 0
        assert "You can successfully interact with Central API (CAPI)" in res.output.decode()

        cs.wait_for_log([
            "*Successfully registered to Central API (CAPI)*",
            "*Registration to online API done*",
        ])
