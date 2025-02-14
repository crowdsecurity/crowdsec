"""
Test bouncer management: pre-installed, run-time installation and removal.
"""

import json
from http import HTTPStatus

import pytest

pytestmark = pytest.mark.docker


def test_register_bouncer_env(crowdsec, flavor: str) -> None:
    """Test installing bouncers at startup, from envvar"""

    env = {"BOUNCER_KEY_bouncer1name": "bouncer1key", "BOUNCER_KEY_bouncer2name": "bouncer2key"}

    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, "/health", want_status=HTTPStatus.OK)
        res = cs.cont.exec_run("cscli bouncers list -o json")
        assert res.exit_code == 0
        j = json.loads(res.output)
        assert len(j) == 2
        bouncer1, bouncer2 = j
        assert bouncer1["name"] == "bouncer1name"
        assert bouncer2["name"] == "bouncer2name"

        # add a second bouncer at runtime
        res = cs.cont.exec_run("cscli bouncers add bouncer3name -k bouncer3key")
        assert res.exit_code == 0
        res = cs.cont.exec_run("cscli bouncers list -o json")
        assert res.exit_code == 0
        j = json.loads(res.output)
        assert len(j) == 3
        bouncer3 = j[2]
        assert bouncer3["name"] == "bouncer3name"

        # remove all bouncers
        res = cs.cont.exec_run("cscli bouncers delete bouncer1name bouncer2name bouncer3name")
        assert res.exit_code == 0
        res = cs.cont.exec_run("cscli bouncers list -o json")
        assert res.exit_code == 0
        j = json.loads(res.output)
        assert len(j) == 0
