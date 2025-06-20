"""
Test pre-installed hub items.
"""

import json
from http import HTTPStatus

import pytest

pytestmark = pytest.mark.docker


def test_preinstalled_hub(crowdsec, flavor: str) -> None:
    """Test hub objects installed in the entrypoint"""
    with crowdsec(flavor=flavor) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, "/health", want_status=HTTPStatus.OK)
        res = cs.cont.exec_run("cscli hub list -o json", stderr=False)
        assert res.exit_code == 0
        j = json.loads(res.output)
        collections = {c["name"]: c for c in j["collections"]}
        assert collections["crowdsecurity/linux"]["status"] == "enabled"
        parsers = {c["name"]: c for c in j["parsers"]}
        assert parsers["crowdsecurity/whitelists"]["status"] == "enabled"
        assert parsers["crowdsecurity/docker-logs"]["status"] == "enabled"
