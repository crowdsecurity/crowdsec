#!/usr/bin/env python

"""
Test pre-installed hub items.
"""

from http import HTTPStatus
import json


def test_preinstalled_hub(crowdsec, flavor):
    """Test hub objects installed in the entrypoint"""
    with crowdsec(flavor=flavor) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli hub list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        collections = {c['name']: c for c in j['collections']}
        assert collections['crowdsecurity/linux']['status'] == 'enabled'
        parsers = {c['name']: c for c in j['parsers']}
        assert parsers['crowdsecurity/whitelists']['status'] == 'enabled'
        assert parsers['crowdsecurity/docker-logs']['status'] == 'enabled'
