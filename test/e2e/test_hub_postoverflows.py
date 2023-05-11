#!/usr/bin/env python

"""
Test postoverflow management
"""

from http import HTTPStatus
import json
import pytest


def test_install_two_postoverflows(crowdsec, flavor):
    """Test installing postoverflows at startup"""
    it1 = 'crowdsecurity/cdn-whitelist'
    it2 = 'crowdsecurity/ipv6_to_range'
    env = {
        'POSTOVERFLOWS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log([
            f'*postoverflows install "{it1}"*',
            f'*postoverflows install "{it2}"*',
            "*Starting processing data*"
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli postoverflows list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['postoverflows']}
        assert items[it1]['status'] == 'enabled'
        assert items[it2]['status'] == 'enabled'


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
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli postoverflows list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['postoverflows']}
        assert it not in items
        logs = cs.log_lines()
        # check that there was no attempt to install
        assert not any(f'postoverflows install "{it}"' in line for line in logs)
