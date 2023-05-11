#!/usr/bin/env python


def test_version_docker_platform(crowdsec, flavor):
    with crowdsec(flavor=flavor) as cs:
        for waiter in cs.log_waiters():
            with waiter as matcher:
                matcher.fnmatch_lines(["*Starting processing data*"])
        res = cs.cont.exec_run('cscli version')
        assert res.exit_code == 0
        assert 'Platform: docker' in res.output.decode()
        res = cs.cont.exec_run('crowdsec -version')
        assert res.exit_code == 0
        assert 'Platform: docker' in res.output.decode()
