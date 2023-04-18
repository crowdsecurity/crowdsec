#!/usr/bin/env python

from http import HTTPStatus

import pytest


def test_metrics_port_default(crowdsec, flavor):
    """Test metrics"""
    metrics_port = 6060
    with crowdsec(flavor=flavor) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        cs.wait_for_http(metrics_port, '/metrics', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run(f'wget -O - http://127.0.0.1:{metrics_port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout


def test_metrics_port_default_ipv6(crowdsec, flavor):
    """Test metrics (ipv6)"""
    pytest.skip('ipv6 not supported yet')
    port = 6060
    with crowdsec(flavor=flavor) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run(f'wget -O - http://[::1]:{port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout


def test_metrics_port(crowdsec, flavor):
    """Test metrics (custom METRICS_PORT)"""
    port = 7070
    env = {
        "METRICS_PORT": port
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run(f'wget -O - http://127.0.0.1:{port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout


def test_metrics_port_ipv6(crowdsec, flavor):
    """Test metrics (custom METRICS_PORT, ipv6)"""
    pytest.skip('ipv6 not supported yet')
    port = 7070
    env = {
        "METRICS_PORT": port
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run(f'wget -O - http://[::1]:{port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout
