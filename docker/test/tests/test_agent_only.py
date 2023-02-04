#!/usr/bin/env python

import random

import pytest

from pytest_cs import wait_for_log, wait_for_http

pytestmark = pytest.mark.docker


def test_split_lapi_agent(crowdsec):
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

    with crowdsec(name=lapiname, environment=lapi_env) as lapi, crowdsec(name=agentname, environment=agent_env) as agent:
        wait_for_log(lapi, "*CrowdSec Local API listening on 0.0.0.0:8080*")
        wait_for_log(agent, "*Starting processing data*")
        wait_for_http(lapi, 8080, '/health')
        res = agent.exec_run('cscli lapi status')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout
