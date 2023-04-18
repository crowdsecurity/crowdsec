#!/usr/bin/env python


# XXX this is redundant, already tested in pytest_cs
def test_crowdsec(crowdsec, flavor):
    with crowdsec(flavor=flavor) as cs:
        for waiter in cs.log_waiters():
            with waiter as matcher:
                matcher.fnmatch_lines(["*Starting processing data*"])
        res = cs.cont.exec_run('sh -c "echo $CI_TESTING"')
        assert res.exit_code == 0
        assert 'true' == res.output.decode().strip()
