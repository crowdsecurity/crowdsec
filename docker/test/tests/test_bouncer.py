#!/usr/bin/env python

"""
Test bouncer management: pre-installed, run-time installation and removal.
"""

import hashlib
from http import HTTPStatus
import json

import pytest

from pytest_cs import wait_for_log, wait_for_http

pytestmark = pytest.mark.docker


def hex512(s):
    """Return the sha512 hash of a string as a hex string"""
    return hashlib.sha512(s.encode()).hexdigest()


def test_register_bouncer_env(crowdsec, flavor):
    """Test installing bouncers at startup, from envvar"""

    env = {
        'BOUNCER_KEY_bouncer1name': 'bouncer1key',
        'BOUNCER_KEY_bouncer2name': 'bouncer2key'
    }

    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        res = cont.exec_run('cscli bouncers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        assert len(j) == 2
        bouncer1, bouncer2 = j
        assert bouncer1['name'] == 'bouncer1name'
        assert bouncer2['name'] == 'bouncer2name'
        assert bouncer1['api_key'] == hex512('bouncer1key')
        assert bouncer2['api_key'] == hex512('bouncer2key')

        # add a second bouncer at runtime
        res = cont.exec_run('cscli bouncers add bouncer3name -k bouncer3key')
        assert res.exit_code == 0
        res = cont.exec_run('cscli bouncers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        assert len(j) == 3
        bouncer3 = j[2]
        assert bouncer3['name'] == 'bouncer3name'
        assert bouncer3['api_key'] == hex512('bouncer3key')

        # remove all bouncers
        res = cont.exec_run('cscli bouncers delete bouncer1name bouncer2name bouncer3name')
        assert res.exit_code == 0
        res = cont.exec_run('cscli bouncers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        assert len(j) == 0
