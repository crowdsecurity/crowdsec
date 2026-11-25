# Copyright (c) 2020-2026 Crowdsec

"""
Test file permissions in the image
"""

import pytest

pytestmark = pytest.mark.docker


def test_staging_readable(crowdsec, flavor: str) -> None:
    """Only secrets and crash dumps in /staging are unreadable by non-root users (#3303)"""
    with crowdsec(flavor=flavor) as cs:
        cs.wait_for_log("*Starting processing data*")
        x = cs.cont.exec_run(
            "find /staging ! -path '*/notifications/*' ! -path '*/data/trace*' ( -type f ! -perm -o+r -o -type d ! -perm -o+rx )"
        )
        assert x.exit_code == 0
        assert set(x.output.decode().split()) == {
            "/staging/etc/crowdsec/local_api_credentials.yaml",
            "/staging/etc/crowdsec/online_api_credentials.yaml",
        }
