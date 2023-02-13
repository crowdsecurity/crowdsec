#!/usr/bin/env python

"""
Test basic behavior of all the image variants
"""

from http import HTTPStatus

import pytest

from pytest_cs import wait_for_log, wait_for_http

pytestmark = pytest.mark.docker


def test_cscli_lapi(crowdsec, flavor):
    """Test if cscli can talk to lapi"""
    with crowdsec(flavor=flavor) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        x = cont.exec_run('cscli lapi status')
        assert x.exit_code == 0
        stdout = x.output.decode()
        assert "You can successfully interact with Local API (LAPI)" in stdout


def test_flavor_content(crowdsec, flavor):
    """Test flavor contents"""
    with crowdsec(flavor=flavor) as cont:
        wait_for_log(cont, "*Starting processing data*")
        wait_for_http(cont, 8080, '/health', want_status=HTTPStatus.OK)
        x = cont.exec_run('ls -1 /var/lib/crowdsec/data/')
        assert x.exit_code == 0
        stdout = x.output.decode()
        if 'slim' in flavor or 'plugins' in flavor:
            assert 'GeoLite2-City.mmdb' not in stdout
            assert 'GeoLite2-ASN.mmdb' not in stdout
        else:
            assert 'GeoLite2-City.mmdb' in stdout
            assert 'GeoLite2-ASN.mmdb' in stdout
        assert 'crowdsec.db' in stdout

        x = cont.exec_run(
            'ls -1 /usr/local/lib/crowdsec/plugins/')
        stdout = x.output.decode()
        if 'slim' in flavor or 'geoip' in flavor:
            # the exact return code and full message depend
            # on the 'ls' implementation (busybox vs coreutils)
            assert x.exit_code != 0
            assert 'No such file or directory' in stdout
            assert 'notification-email' not in stdout
            assert 'notification-http' not in stdout
            assert 'notification-slack' not in stdout
            assert 'notification-splunk' not in stdout
        else:
            assert x.exit_code == 0
            assert 'notification-email' in stdout
            assert 'notification-http' in stdout
            assert 'notification-slack' in stdout
            assert 'notification-splunk' in stdout
