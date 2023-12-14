#!/usr/bin/env python

"""
Test agent-lapi and cscli-lapi communication via TLS, on the same container.
"""

import uuid

from pytest_cs import Status

import pytest

pytestmark = pytest.mark.docker


def test_missing_key_file(crowdsec, flavor):
    """Test that cscli and agent can communicate to LAPI with TLS"""

    env = {
        'CERT_FILE': '/etc/ssl/crowdsec/cert.pem',
        'USE_TLS': 'true',
    }

    with crowdsec(flavor=flavor, environment=env, wait_status=Status.EXITED) as cs:
        # XXX: this message appears twice, is that normal?
        cs.wait_for_log("*while starting API server: missing TLS key file*")


def test_missing_cert_file(crowdsec, flavor):
    """Test that cscli and agent can communicate to LAPI with TLS"""

    env = {
        'KEY_FILE': '/etc/ssl/crowdsec/cert.key',
        'USE_TLS': 'true',
    }

    with crowdsec(flavor=flavor, environment=env, wait_status=Status.EXITED) as cs:
        cs.wait_for_log("*while starting API server: missing TLS cert file*")


def test_tls_missing_ca(crowdsec, flavor, certs_dir):
    """Missing CA cert, unknown authority"""

    env = {
        'CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    volumes = {
        certs_dir(lapi_hostname='lapi'): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(flavor=flavor, environment=env, volumes=volumes, wait_status=Status.EXITED) as cs:
        cs.wait_for_log("*certificate signed by unknown authority*")


def test_tls_legacy_var(crowdsec, flavor, certs_dir):
    """Test server-only certificate, legacy variables"""

    env = {
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    volumes = {
        certs_dir(lapi_hostname='lapi'): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log("*Starting processing data*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, '/health', want_status=None)
        x = cs.cont.exec_run('cscli lapi status')
        assert x.exit_code == 0
        stdout = x.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout


def test_tls_mutual_monolith(crowdsec, flavor, certs_dir):
    """Server and client certificates, on the same container"""

    env = {
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'CLIENT_CERT_FILE': '/etc/ssl/crowdsec/agent.crt',
        'CLIENT_KEY_FILE': '/etc/ssl/crowdsec/agent.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    volumes = {
        certs_dir(lapi_hostname='lapi'): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log("*Starting processing data*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, '/health', want_status=None)
        x = cs.cont.exec_run('cscli lapi status')
        assert x.exit_code == 0
        stdout = x.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout


def test_tls_lapi_var(crowdsec, flavor, certs_dir):
    """Test server-only certificate, lapi variables"""

    env = {
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    volumes = {
        certs_dir(lapi_hostname='lapi'): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log("*Starting processing data*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, '/health', want_status=None)
        x = cs.cont.exec_run('cscli lapi status')
        assert x.exit_code == 0
        stdout = x.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout

# TODO: bad lapi hostname
# the cert is valid, but has a CN that doesn't match the hostname
# we must set insecure_skip_verify to true to use it


def test_tls_split_lapi_agent(crowdsec, flavor, certs_dir):
    """Server-only certificate, split containers"""

    rand = uuid.uuid1()
    lapiname = 'lapi-' + str(rand)
    agentname = 'agent-' + str(rand)

    lapi_env = {
        'USE_TLS': 'true',
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'AGENT_USERNAME': 'testagent',
        'AGENT_PASSWORD': 'testpassword',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    agent_env = {
        'USE_TLS': 'true',
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'AGENT_USERNAME': 'testagent',
        'AGENT_PASSWORD': 'testpassword',
        'LOCAL_API_URL': f'https://{lapiname}:8080',
        'DISABLE_LOCAL_API': 'true',
        'CROWDSEC_FEATURE_DISABLE_HTTP_RETRY_BACKOFF': 'false',
    }

    volumes = {
        certs_dir(lapi_hostname=lapiname): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    cs_lapi = crowdsec(flavor=flavor, name=lapiname, environment=lapi_env, volumes=volumes)
    cs_agent = crowdsec(flavor=flavor, name=agentname, environment=agent_env, volumes=volumes)

    with cs_lapi as lapi:
        lapi.wait_for_log([
            "*(tls) Client Auth Type set to VerifyClientCertIfGiven*",
            "*CrowdSec Local API listening on *:8080*"
        ])
        # TODO: wait_for_https
        lapi.wait_for_http(8080, '/health', want_status=None)
        with cs_agent as agent:
            agent.wait_for_log("*Starting processing data*")
            res = agent.cont.exec_run('cscli lapi status')
            assert res.exit_code == 0
            stdout = res.output.decode()
            assert "You can successfully interact with Local API (LAPI)" in stdout
            res = lapi.cont.exec_run('cscli lapi status')
            assert res.exit_code == 0
            stdout = res.output.decode()
            assert "You can successfully interact with Local API (LAPI)" in stdout


def test_tls_mutual_split_lapi_agent(crowdsec, flavor, certs_dir):
    """Server and client certificates, split containers"""

    rand = uuid.uuid1()
    lapiname = 'lapi-' + str(rand)
    agentname = 'agent-' + str(rand)

    lapi_env = {
        'USE_TLS': 'true',
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    agent_env = {
        'USE_TLS': 'true',
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'CLIENT_CERT_FILE': '/etc/ssl/crowdsec/agent.crt',
        'CLIENT_KEY_FILE': '/etc/ssl/crowdsec/agent.key',
        'LOCAL_API_URL': f'https://{lapiname}:8080',
        'DISABLE_LOCAL_API': 'true',
        'CROWDSEC_FEATURE_DISABLE_HTTP_RETRY_BACKOFF': 'false',
    }

    volumes = {
        certs_dir(lapi_hostname=lapiname): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    cs_lapi = crowdsec(flavor=flavor, name=lapiname, environment=lapi_env, volumes=volumes)
    cs_agent = crowdsec(flavor=flavor, name=agentname, environment=agent_env, volumes=volumes)

    with cs_lapi as lapi:
        lapi.wait_for_log([
            "*(tls) Client Auth Type set to VerifyClientCertIfGiven*",
            "*CrowdSec Local API listening on *:8080*"
        ])
        # TODO: wait_for_https
        lapi.wait_for_http(8080, '/health', want_status=None)
        with cs_agent as agent:
            agent.wait_for_log("*Starting processing data*")
            res = agent.cont.exec_run('cscli lapi status')
            assert res.exit_code == 0
            stdout = res.output.decode()
            assert "You can successfully interact with Local API (LAPI)" in stdout
            res = lapi.cont.exec_run('cscli lapi status')
            assert res.exit_code == 0
            stdout = res.output.decode()
            assert "You can successfully interact with Local API (LAPI)" in stdout


def test_tls_client_ou(crowdsec, certs_dir):
    """Check behavior of client certificate vs AGENTS_ALLOWED_OU"""

    rand = uuid.uuid1()
    lapiname = 'lapi-' + str(rand)
    agentname = 'agent-' + str(rand)

    lapi_env = {
        'USE_TLS': 'true',
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    agent_env = {
        'USE_TLS': 'true',
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'CLIENT_CERT_FILE': '/etc/ssl/crowdsec/agent.crt',
        'CLIENT_KEY_FILE': '/etc/ssl/crowdsec/agent.key',
        'LOCAL_API_URL': f'https://{lapiname}:8080',
        'DISABLE_LOCAL_API': 'true',
        'CROWDSEC_FEATURE_DISABLE_HTTP_RETRY_BACKOFF': 'false',
    }

    volumes = {
        certs_dir(lapi_hostname=lapiname, agent_ou='custom-client-ou'): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    cs_lapi = crowdsec(name=lapiname, environment=lapi_env, volumes=volumes)
    cs_agent = crowdsec(name=agentname, environment=agent_env, volumes=volumes)

    with cs_lapi as lapi:
        lapi.wait_for_log([
            "*(tls) Client Auth Type set to VerifyClientCertIfGiven*",
            "*CrowdSec Local API listening on *:8080*"
        ])
        # TODO: wait_for_https
        lapi.wait_for_http(8080, '/health', want_status=None)
        with cs_agent as agent:
            lapi.wait_for_log([
                "*client certificate OU (?custom-client-ou?) doesn't match expected OU (?agent-ou?)*",
            ])

    lapi_env['AGENTS_ALLOWED_OU'] = 'custom-client-ou'

    # change container names to avoid conflict
    # recreate certificates because they need the new hostname

    rand = uuid.uuid1()
    lapiname = 'lapi-' + str(rand)
    agentname = 'agent-' + str(rand)

    agent_env['LOCAL_API_URL'] = f'https://{lapiname}:8080'

    volumes = {
        certs_dir(lapi_hostname=lapiname, agent_ou='custom-client-ou'): {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    cs_lapi = crowdsec(name=lapiname, environment=lapi_env, volumes=volumes)
    cs_agent = crowdsec(name=agentname, environment=agent_env, volumes=volumes)

    with cs_lapi as lapi:
        lapi.wait_for_log([
            "*(tls) Client Auth Type set to VerifyClientCertIfGiven*",
            "*CrowdSec Local API listening on *:8080*"
        ])
        # TODO: wait_for_https
        lapi.wait_for_http(8080, '/health', want_status=None)
        with cs_agent as agent:
            agent.wait_for_log("*Starting processing data*")
            res = agent.cont.exec_run('cscli lapi status')
            assert res.exit_code == 0
            stdout = res.output.decode()
            assert "You can successfully interact with Local API (LAPI)" in stdout
            res = lapi.cont.exec_run('cscli lapi status')
            assert res.exit_code == 0
            stdout = res.output.decode()
            assert "You can successfully interact with Local API (LAPI)" in stdout
