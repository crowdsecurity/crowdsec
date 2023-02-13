#!/usr/bin/env python

"""
Test parser management
"""

from http import HTTPStatus
import json

from pytest_cs import wait_for_log, wait_for_http

import pytest

pytestmark = pytest.mark.docker


def test_install_two_parsers(crowdsec, flavor):
    """Test installing parsers at startup"""
    it1 = 'crowdsecurity/cpanel-logs'
    it2 = 'crowdsecurity/cowrie-logs'
    env = {
        'PARSERS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli parsers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['parsers']}
        assert items[it1]['status'] == 'enabled'
        assert items[it2]['status'] == 'enabled'
        logs = cont.logs().decode().splitlines()
        assert any(f'parsers install "{it1}"' in line for line in logs)
        assert any(f'parsers install "{it2}"' in line for line in logs)


# XXX check that the parser is preinstalled by default
def test_disable_parser(crowdsec, flavor):
    """Test removing a pre-installed parser at startup"""
    it = 'crowdsecurity/whitelists'
    env = {
        'DISABLE_PARSERS': it
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli parsers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['parsers']}
        assert it not in items
        logs = cont.logs().decode().splitlines()
        assert any(f'parsers remove "{it}"' in line for line in logs)


def test_install_and_disable_parser(crowdsec, flavor):
    """Declare a parser to install AND disable: disable wins"""
    it = 'crowdsecurity/cpanel-logs'
    env = {
        'PARSERS': it,
        'DISABLE_PARSERS': it,
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli parsers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['parsers']}
        assert it not in items
        logs = cont.logs().decode().splitlines()
        # check that there was no attempt to install
        assert not any(f'parsers install "{it}"' in line for line in logs)
