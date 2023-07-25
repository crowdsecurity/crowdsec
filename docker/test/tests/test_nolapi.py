#!/usr/bin/env python

from pytest_cs import Status

import pytest

pytestmark = pytest.mark.docker


def test_no_agent(crowdsec, flavor):
    """Test DISABLE_LOCAL_API=true (failing stand-alone container)"""
    env = {
        'DISABLE_LOCAL_API': 'true',
    }

    # if an alternative lapi url is not defined, the container should exit

    with crowdsec(flavor=flavor, environment=env, wait_status=Status.EXITED) as cs:
        cs.wait_for_log("*dial tcp 0.0.0.0:8080: connect: connection refused*")
