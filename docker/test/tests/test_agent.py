#!/usr/bin/env python

from http import HTTPStatus

import pytest

pytestmark = pytest.mark.docker


def test_no_agent(crowdsec, flavor):
    """Test DISABLE_AGENT=true"""
    env = {
        'DISABLE_AGENT': 'true',
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*CrowdSec Local API listening on *:8080*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout


def test_machine_register(crowdsec, flavor, tmp_path_factory):
    """A local agent is always registered for use by cscli"""

    data_dir = tmp_path_factory.mktemp('data')

    env = {
        'DISABLE_AGENT': 'true',
    }

    volumes = {
        data_dir: {'bind': '/var/lib/crowdsec/data', 'mode': 'rw'},
    }

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log([
                "*Generate local agent credentials*",
                "*CrowdSec Local API listening on *:8080*",
            ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout

    # The local agent is not registered, because we didn't persist local_api_credentials.yaml

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log([
                "*Generate local agent credentials*",
                "*CrowdSec Local API listening on *:8080*",
            ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout

    config_dir = tmp_path_factory.mktemp('config')

    volumes[config_dir] = {'bind': '/etc/crowdsec', 'mode': 'rw'}

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log([
                "*Generate local agent credentials*",
                "*CrowdSec Local API listening on *:8080*",
            ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout

    # The local agent is now already registered

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log([
                "*Local agent already registered*",
                "*CrowdSec Local API listening on *:8080*",
            ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout
