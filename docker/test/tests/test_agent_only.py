#!/usr/bin/env python

from http import HTTPStatus
import random

import pytest

pytestmark = pytest.mark.docker


def test_split_lapi_agent(crowdsec, flavor):
    rand = str(random.randint(0, 10000))
    lapiname = f'lapi-{rand}'
    agentname = f'agent-{rand}'

    lapi_env = {
        'AGENT_USERNAME': 'testagent',
        'AGENT_PASSWORD': 'testpassword',
    }

    agent_env = {
        'AGENT_USERNAME': 'testagent',
        'AGENT_PASSWORD': 'testpassword',
        'DISABLE_LOCAL_API': 'true',
        'LOCAL_API_URL': f'http://{lapiname}:8080',
    }

    cs_lapi = crowdsec(name=lapiname, environment=lapi_env, flavor=flavor)
    cs_agent = crowdsec(name=agentname, environment=agent_env, flavor=flavor)

    with cs_lapi as lapi:
        lapi.wait_for_log("*CrowdSec Local API listening on *:8080*")
        lapi.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        with cs_agent as agent:
            agent.wait_for_log("*Starting processing data*")
            res = agent.cont.exec_run('cscli lapi status')
            assert res.exit_code == 0
            stdout = res.output.decode()
            assert "You can successfully interact with Local API (LAPI)" in stdout
