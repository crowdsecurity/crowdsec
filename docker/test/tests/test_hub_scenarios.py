#!/usr/bin/env python

"""
Test scenario management
"""

from http import HTTPStatus
import json

from pytest_cs import wait_for_log, wait_for_http

import pytest

pytestmark = pytest.mark.docker


def test_install_two_scenarios(crowdsec, flavor):
    """Test installing scenarios at startup"""
    it1 = 'crowdsecurity/cpanel-bf-attempt'
    it2 = 'crowdsecurity/asterisk_bf'
    env = {
        'SCENARIOS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, [
            f'*scenarios install "{it1}*"',
            f'*scenarios install "{it2}*"',
            "*Starting processing data*"
        ])
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli scenarios list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['scenarios']}
        assert items[it1]['status'] == 'enabled'
        assert items[it2]['status'] == 'enabled'


def test_disable_scenario(crowdsec, flavor):
    """Test removing a pre-installed scenario at startup"""
    it = 'crowdsecurity/ssh-bf'
    env = {
        'DISABLE_SCENARIOS': it
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, [
            f'*scenarios remove "{it}"*',
            "*Starting processing data*"
        ])
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli scenarios list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['scenarios']}
        assert it not in items


def test_install_and_disable_scenario(crowdsec, flavor):
    """Declare a scenario to install AND disable: disable wins"""
    it = 'crowdsecurity/asterisk_bf'
    env = {
        'SCENARIOS': it,
        'DISABLE_SCENARIOS': it,
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli scenarios list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['scenarios']}
        assert it not in items
        logs = cont.logs().decode().splitlines()
        # check that there was no attempt to install
        assert not any(f'scenarios install "{it}"' in line for line in logs)
