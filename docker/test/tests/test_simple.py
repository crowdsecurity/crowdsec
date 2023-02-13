#!/usr/bin/env python

from pytest_cs import log_waiters

import pytest

pytestmark = pytest.mark.docker


# XXX this is redundant, already tested in pytest_cs
def test_crowdsec(crowdsec):
    with crowdsec() as cont:
        for waiter in log_waiters(cont):
            with waiter as matcher:
                matcher.fnmatch_lines(["*Starting processing data*"])
        res = cont.exec_run('sh -c "echo $CI_TESTING"')
        assert res.exit_code == 0
        assert 'true' == res.output.decode().strip()
