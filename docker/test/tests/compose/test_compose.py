#!/usr/bin/env python

import time

import pytest
import requests

pytestmark = pytest.mark.compose


def test_compose_simple(compose, datadir):
    with compose(datadir / 'docker-compose.yml') as project:
        j = project.ps()
        assert len(j) == 1
        assert j[0]['Name'] == 'test_compose-server-1'
        assert j[0]['State'] == 'running'
        assert j[0]['Publishers'][0]['TargetPort'] == 8000
        port = j[0]['Publishers'][0]['PublishedPort']
        # XXX: should retry with a timeout
        time.sleep(.5)
        assert requests.get(f'http://localhost:{port}').status_code == 200
