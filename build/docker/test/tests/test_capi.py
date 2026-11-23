# Copyright (c) 2020-2026 Crowdsec

from http import HTTPStatus

import pytest

pytestmark = pytest.mark.docker


def test_no_capi(crowdsec, flavor: str) -> None:
    """Test no CAPI (disabled by default in tests)"""

    env = {
        "DISABLE_ONLINE_API": "true",
    }

    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, "/health", want_status=HTTPStatus.OK)
        res = cs.cont.exec_run("cscli capi status")
        assert res.exit_code == 1
        assert "You can successfully interact with Central API (CAPI)" not in res.output.decode()

        logs = cs.log_lines()
        assert not any("Successfully registered to Central API (CAPI)" in line for line in logs)
        assert not any("Registration to online API done" in line for line in logs)


def test_capi(crowdsec, flavor: str) -> None:
    """Test CAPI"""

    env = {
        "DISABLE_ONLINE_API": "false",
    }

    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, "/health", want_status=HTTPStatus.OK)
        res = cs.cont.exec_run("cscli capi status")
        assert res.exit_code == 0
        assert "You can successfully interact with Central API (CAPI)" in res.output.decode()

        cs.wait_for_log(
            [
                "*Successfully registered to Central API (CAPI)*",
                "*Registration to online API done*",
            ]
        )


def test_capi_register_creds_mode(crowdsec, flavor: str) -> None:
    """A CAPI registration with no credentials file writes it owner-only"""
    env = {"DISABLE_ONLINE_API": "false"}
    # the image ships an empty 0600 file; a user-provided config dir may not
    entrypoint = ["sh", "-c", "rm /staging/etc/crowdsec/online_api_credentials.yaml && exec /bin/bash /docker_start.sh"]

    with crowdsec(flavor=flavor, environment=env, entrypoint=entrypoint) as cs:
        cs.wait_for_log("*Registration to online API done*")
        res = cs.cont.exec_run("stat -c %a /etc/crowdsec/online_api_credentials.yaml")
        assert res.output.decode().strip() == "600"
