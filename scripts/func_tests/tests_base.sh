#! /usr/bin/env bash
# -*- coding: utf-8 -*-

# sourced by other functional tests

#shellcheck source=lib/wrap-init.sh
. "$(dirname "$(readlink -f "$0")")/lib/wrap-init.sh"

PACKAGE_PATH="${PACKAGE_PATH:-./crowdsec.deb}"

CSCLI_BIN="cscli"
CSCLI="sudo ${CSCLI_BIN}"
JQ="jq -e"

LC_ALL=C

CROWDSEC="sudo crowdsec"
CROWDSEC_PROCESS="crowdsec"

# helpers
function fail {
    echo "ACTION FAILED, STOP : $@"
    caller
    exit 1
}

function pathadd {
    if [ -d "$1" ] && [[ ":$PATH:" != *":$1:"* ]]; then
        PATH="${PATH:+"$PATH:"}$1"
    fi
}

function wait_for_service {
    count=0
    while ! nc -z localhost 6060; do   
        sleep 0.5
        ((count ++))
        if [[ $count == 21 ]]; then
            fail "$@"
        fi
    done
}

pathadd /usr/sbin

if [ -f /etc/systemd/system/crowdsec.service ]; then
    SYSTEMD_SERVICE_FILE=/etc/systemd/system/crowdsec.service
elif  [ -f /usr/lib/systemd/system/crowdsec.service ]; then
    SYSTEMD_SERVICE_FILE=/usr/lib/systemd/system/crowdsec.service
elif  [ -f /lib/systemd/system/crowdsec.service ]; then
    SYSTEMD_SERVICE_FILE=/lib/systemd/system/crowdsec.service
fi
