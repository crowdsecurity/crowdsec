#!/usr/bin/env python

"""
Test scenario management
"""

from http import HTTPStatus
import json

import pytest

pytestmark = pytest.mark.docker


def test_install_two_scenarios(crowdsec, flavor):
    """Test installing scenarios at startup"""
    it1 = 'crowdsecurity/cpanel-bf-attempt'
    it2 = 'crowdsecurity/asterisk_bf'
    env = {
        'SCENARIOS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log([
            f'*scenarios install "{it1}"*',
            f'*scenarios install "{it2}"*',
            "*Starting processing data*"
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli scenarios list -o json')
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
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log([
            f'*scenarios remove "{it}"*',
            "*Starting processing data*"
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli scenarios list -o json')
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
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli scenarios list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['scenarios']}
        assert it not in items
        logs = cs.cont.logs().decode().splitlines()
        # check that there was no attempt to install
        assert not any(f'scenarios install "{it}"' in line for line in logs)
