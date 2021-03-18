#! /usr/bin/env bash
# -*- coding: utf-8 -*-


# sourced by other functionnal tests

PACKAGE_PATH="${PACKAGE_PATH:-./crowdsec.deb}"

CSCLI_BIN="cscli"
CSCLI="sudo ${CSCLI_BIN}"
JQ="jq -e"

SYSTEMCTL="sudo systemctl --no-pager"

# helpers
function fail {
    echo "ACTION FAILED, STOP : $@"
    caller
    exit 1
}
