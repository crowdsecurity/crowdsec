from http import HTTPStatus

import pytest
import yaml

pytestmark = pytest.mark.docker


def test_capi_whitelists(crowdsec, tmp_path_factory: pytest.TempPathFactory, flavor: str) -> None:
    """Test CAPI_WHITELISTS_PATH"""
    env = {"CAPI_WHITELISTS_PATH": "/path/to/whitelists.yaml"}

    whitelists = tmp_path_factory.mktemp("whitelists")
    with (whitelists / "whitelists.yaml").open("w") as f:
        yaml.dump({"ips": ["1.2.3.4", "2.3.4.5"], "cidrs": ["1.2.3.0/24"]}, f)

    volumes = {whitelists / "whitelists.yaml": {"bind": "/path/to/whitelists.yaml", "mode": "ro"}}

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, "/health", want_status=HTTPStatus.OK)
        res = cs.cont.exec_run("cscli config show-yaml")
        assert res.exit_code == 0
        stdout = res.output.decode()
        y = yaml.safe_load(stdout)
        assert y["api"]["server"]["capi_whitelists_path"] == "/path/to/whitelists.yaml"
