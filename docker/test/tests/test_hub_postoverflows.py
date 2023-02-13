#!/usr/bin/env python

"""
Test postoverflow management
"""

from http import HTTPStatus
import json
import pytest

from pytest_cs import wait_for_log, wait_for_http

pytestmark = pytest.mark.docker


def test_install_two_postoverflows(crowdsec, flavor):
    """Test installing postoverflows at startup"""
    it1 = 'crowdsecurity/cdn-whitelist'
    it2 = 'crowdsecurity/ipv6_to_range'
    env = {
        'POSTOVERFLOWS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli postoverflows list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['postoverflows']}
        assert items[it1]['status'] == 'enabled'
        assert items[it2]['status'] == 'enabled'
        logs = cont.logs().decode().splitlines()
        assert any(f'postoverflows install "{it1}"' in line for line in logs)
        assert any(f'postoverflows install "{it2}"' in line for line in logs)


def test_disable_postoverflow():
    """Test removing a pre-installed postoverflow at startup"""
    pytest.skip("we don't preinstall postoverflows")


def test_install_and_disable_postoverflow(crowdsec, flavor):
    """Declare a postoverflow to install AND disable: disable wins"""
    it = 'crowdsecurity/cdn-whitelist'
    env = {
        'POSTOVERFLOWS': it,
        'DISABLE_POSTOVERFLOWS': it,
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli postoverflows list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['postoverflows']}
        assert it not in items
        logs = cont.logs().decode().splitlines()
        # check that there was no attempt to install
        assert not any(f'postoverflows install "{it}"' in line for line in logs)
