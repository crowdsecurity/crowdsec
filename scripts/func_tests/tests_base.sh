#! /usr/bin/env bash
# -*- coding: utf-8 -*-


# sourced by other functionnal tests

PACKAGE_PATH="${PACKAGE_PATH:-./crowdsec.deb}"

CSCLI_BIN="cscli"
CSCLI="sudo ${CSCLI_BIN}"
JQ="jq -e"

LC_ALL=C
SYSTEMCTL="sudo systemctl --no-pager"

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

pathadd /usr/sbin
