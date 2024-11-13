#!/usr/bin/env python

"""
Test bind-mounting local items
"""

from http import HTTPStatus
import json

import pytest

pytestmark = pytest.mark.docker


def test_inject_local_item(crowdsec, tmp_path_factory, flavor):
    """Test mounting a custom whitelist at startup"""

    localitems = tmp_path_factory.mktemp('localitems')
    custom_whitelists = localitems / 'custom_whitelists.yaml'

    with open(custom_whitelists, 'w') as f:
        f.write('{"whitelist":{"reason":"Good IPs","ip":["1.2.3.4"]}}')

    volumes = {
        custom_whitelists: {'bind': '/etc/crowdsec/parsers/s02-enrich/custom_whitelists.yaml'}
    }

    with crowdsec(flavor=flavor, volumes=volumes) as cs:
        cs.wait_for_log([
            "*Starting processing data*"
        ])
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)

        # the parser should be enabled
        res = cs.cont.exec_run('cscli parsers list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        items = {c['name']: c for c in j['parsers']}
        assert items['custom_whitelists.yaml']['status'] == 'enabled,local'

        # regression test: the linux collection should not be tainted
        # (the parsers were not copied from /staging when using "cp -an" with local parsers)
        res = cs.cont.exec_run('cscli collections inspect crowdsecurity/linux -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        # crowdsec <= 1.5.5 omits a "tainted" when it's false
        assert j.get('tainted', False) is False
