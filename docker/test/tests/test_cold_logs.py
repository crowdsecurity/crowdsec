import datetime

import pytest
from pytest_cs import Status

pytestmark = pytest.mark.docker


def test_cold_logs(crowdsec, tmp_path_factory: pytest.TempPathFactory, flavor: str) -> None:
    env = {
        "DSN": "file:///var/log/toto.log",
    }

    logs = tmp_path_factory.mktemp("logs")

    now = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(minutes=1)
    with (logs / "toto.log").open("w") as f:
        # like date '+%b %d %H:%M:%S' but in python
        for i in range(10):
            ts = (now + datetime.timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
            _ = f.write(ts + " sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.172 port 35424\n")

    volumes = {
        logs / "toto.log": {"bind": "/var/log/toto.log", "mode": "ro"},
    }

    # missing type

    with crowdsec(flavor=flavor, environment=env, volumes=volumes, wait_status=Status.EXITED) as cs:
        cs.wait_for_log("*-dsn requires a -type argument*")

    env["TYPE"] = "syslog"

    with crowdsec(flavor=flavor, environment=env, volumes=volumes) as cs:
        cs.wait_for_log(
            [
                "*Adding file /var/log/toto.log to filelist*",
                "*reading /var/log/toto.log at once*",
                "*Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 5s)*",
                "*crowdsec shutdown*",
            ]
        )


def test_cold_logs_missing_dsn(crowdsec, flavor: str) -> None:
    env = {
        "TYPE": "syslog",
    }

    with crowdsec(flavor=flavor, environment=env, wait_status=Status.EXITED) as cs:
        cs.wait_for_log("*-type requires a -dsn argument*")
