#!/usr/bin/env python

"""
Test collection management
"""

from http import HTTPStatus
import json

import pytest

pytestmark = pytest.mark.docker


def test_install_two_collections(crowdsec, flavor):
    """Test installing collections at startup"""
    it1 = 'crowdsecurity/apache2'
    it2 = 'crowdsecurity/asterisk'
    env = {
        'COLLECTIONS': f'{it1} {it2}'
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['collections']}
        assert items[it1]['status'] == 'enabled'
        assert items[it2]['status'] == 'enabled'
        cs.wait_for_log([
            # f'*collections install "{it1}"*'
            # f'*collections install "{it2}"*'
            f'*Enabled collections: {it1}*',
            f'*Enabled collections: {it2}*',
        ])


def test_disable_collection(crowdsec, flavor):
    """Test removing a pre-installed collection at startup"""
    it = 'crowdsecurity/linux'
    env = {
        'DISABLE_COLLECTIONS': it
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['collections']}
        assert it not in items
        cs.wait_for_log([
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
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name'] for c in j['collections']}
        assert it not in items
        logs = cs.log_lines()
        # check that there was no attempt to install
        assert not any(f'Enabled collections: {it}' in line for line in logs)


# already done in bats, prividing here as example of a somewhat complex test
def test_taint_bubble_up(crowdsec, tmp_path_factory, flavor):
    coll = 'crowdsecurity/nginx'
    env = {
        'COLLECTIONS': f'{coll}'
    }

    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['collections']}
        # implicit check for tainted=False
        assert items[coll]['status'] == 'enabled'
        cs.wait_for_log([
            f'*Enabled collections: {coll}*',
        ])

        scenario = 'crowdsecurity/http-crawl-non_statics'

        # the description won't be read back, it's from the index
        yq_command = f"yq -e -i '.description=\"tainted\"' /etc/crowdsec/hub/scenarios/{scenario}.yaml"
        res = cs.cont.exec_run(yq_command)
        assert res.exit_code == 0

        res = cs.cont.exec_run(f'cscli scenarios inspect {scenario} -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        assert j['tainted'] is True

        res = cs.cont.exec_run('cscli collections list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['collections']}
        assert items['crowdsecurity/nginx']['status'] == 'enabled,tainted'
        assert items['crowdsecurity/base-http-scenarios']['status'] == 'enabled,tainted'
