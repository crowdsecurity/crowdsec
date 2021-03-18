#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh


## version

${CSCLI} version || fail "cannot run cscli version"


## alerts

# alerts list at startup should just return one entry : comunity pull
${CSCLI} alerts list -ojson | ${JQ} '. | length >= 1' || fail "expected at least one entry from cscli alerts list"


## capi

${CSCLI} capi status || fail "capi status should be ok"


## config

${CSCLI} config show || fail "failed to show config"

${CSCLI} config backup ./test || fail "failed to backup config"

## lapi

${CSCLI} lapi status || fail "lapi status failed"

## metrics
${CSCLI} metrics || fail "failed to get metrics"

