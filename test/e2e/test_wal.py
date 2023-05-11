#!/usr/bin/env python

from http import HTTPStatus


def test_use_wal_default(crowdsec, flavor):
    """Test USE_WAL default"""
    with crowdsec(flavor=flavor) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli config show --key Config.DbConfig.UseWal -o json')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "false" in stdout


def test_use_wal_true(crowdsec, flavor):
    """Test USE_WAL=true"""
    env = {
        'USE_WAL': 'true',
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli config show --key Config.DbConfig.UseWal -o json')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "true" in stdout


def test_use_wal_false(crowdsec, flavor):
    """Test USE_WAL=false"""
    env = {
        'USE_WAL': 'false',
    }
    with crowdsec(flavor=flavor, environment=env) as cs:
        cs.wait_for_log("*Starting processing data*")
        cs.wait_for_http(8080, '/health', want_status=HTTPStatus.OK)
        res = cs.cont.exec_run('cscli config show --key Config.DbConfig.UseWal -o json')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "false" in stdout
