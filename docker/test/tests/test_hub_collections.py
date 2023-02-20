#!/usr/bin/env python

"""
Test collection management
"""

from http import HTTPStatus
import json

from pytest_cs import wait_for_log, wait_for_http

import pytest

pytestmark = pytest.mark.docker


def test_install_two_collections(crowdsec, flavor):
    """Test installing collections at startup"""
    it1 = 'crowdsecurity/apache2'
    it2 = 'crowdsecurity/asterisk'
    env = {
        'COLLECTIONS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['collections']}
        assert items[it1]['status'] == 'enabled'
        assert items[it2]['status'] == 'enabled'
        wait_for_log(cont, [
            # f'*collections install "{it1}"*'
            # f'*collections install "{it2}"*'
            f'*Enabled collections : {it1}*',
            f'*Enabled collections : {it2}*',
        ])


def test_disable_collection(crowdsec, flavor):
    """Test removing a pre-installed collection at startup"""
    it = 'crowdsecurity/linux'
    env = {
        'DISABLE_COLLECTIONS': it
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['collections']}
        assert it not in items
        wait_for_log(cont, [
            # f'*collections remove "{it}*",
            f'*Removed symlink [[]{it}[]]*',
        ])


def test_install_and_disable_collection(crowdsec, flavor):
    """Declare a collection to install AND disable: disable wins"""
    it = 'crowdsecurity/apache2'
    env = {
        'COLLECTIONS': it,
        'DISABLE_COLLECTIONS': it,
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['collections']}
        assert it not in items
        logs = cont.logs().decode().splitlines()
        # check that there was no attempt to install
        assert not any(f'Enabled collections : {it}' in line for line in logs)
