#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh



## status / start / stop
# service should be up
pidof crowdsec || fail "crowdsec process shouldn't be running"
${SYSTEMCTL} status crowdsec || fail "systemctl status crowdsec failed"

#shut it down
${SYSTEMCTL} stop crowdsec || fail "failed to stop service"
${SYSTEMCTL} status crowdsec && fail "crowdsec should be down"
pidof crowdsec && fail "crowdsec process shouldn't be running"

#start it again
${SYSTEMCTL} start crowdsec || fail "failed to stop service"
${SYSTEMCTL} status crowdsec || fail "crowdsec should be down"
pidof crowdsec || fail "crowdsec process shouldn't be running"

#restart it
${SYSTEMCTL} restart crowdsec || fail "failed to stop service"
${SYSTEMCTL} status crowdsec || fail "crowdsec should be down"
pidof crowdsec || fail "crowdsec process shouldn't be running"




## version

${CSCLI} version || fail "cannot run cscli version"


## alerts

# alerts list at startup should just return one entry : comunity pull
sleep 5
${CSCLI} alerts list -ojson  | ${JQ} '. | length >= 1' || fail "expected at least one entry from cscli alerts list"


## capi

${CSCLI} capi status || fail "capi status should be ok"


## config

${CSCLI} config show || fail "failed to show config"

${CSCLI} config backup ./test || fail "failed to backup config"

## lapi

${CSCLI} lapi status || fail "lapi status failed"

## metrics
${CSCLI} metrics || fail "failed to get metrics"

