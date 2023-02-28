#!/usr/bin/env python

"""
Test parser management
"""

from http import HTTPStatus
import json

import pytest

pytestmark = pytest.mark.docker


def test_install_two_parsers(crowdsec, flavor):
    """Test installing parsers at startup"""
    it1 = 'crowdsecurity/cpanel-logs'
    it2 = 'crowdsecurity/cowrie-logs'
    env = {
        'PARSERS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log([
            f'*parsers install "{it1}"*',
            f'*parsers install "{it2}"*',
            "*Starting processing data*"
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli parsers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['parsers']}
        assert items[it1]['status'] == 'enabled'
        assert items[it2]['status'] == 'enabled'


# XXX check that the parser is preinstalled by default
def test_disable_parser(crowdsec, flavor):
    """Test removing a pre-installed parser at startup"""
    it = 'crowdsecurity/whitelists'
    env = {
        'DISABLE_PARSERS': it
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log([
            f'*parsers remove "{it}"*',
            "*Starting processing data*",
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli parsers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['parsers']}
        assert it not in items


def test_install_and_disable_parser(crowdsec, flavor):
    """Declare a parser to install AND disable: disable wins"""
    it = 'crowdsecurity/cpanel-logs'
    env = {
        'PARSERS': it,
        'DISABLE_PARSERS': it,
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli parsers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['parsers']}
        assert it not in items
        logs = cs.log_lines()
        # check that there was no attempt to install
        assert not any(f'parsers install "{it}"' in line for line in logs)
