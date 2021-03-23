#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh



## status / start / stop
# service should be up
pidof crowdsec || fail "crowdsec process should be running"
${SYSTEMCTL} status crowdsec || fail "systemctl status crowdsec failed"

#shut it down
${SYSTEMCTL} stop crowdsec || fail "failed to stop service"
${SYSTEMCTL} status crowdsec && fail "crowdsec should be down"
pidof crowdsec && fail "crowdsec process shouldn't be running"

#start it again
${SYSTEMCTL} start crowdsec || fail "failed to stop service"
${SYSTEMCTL} status crowdsec || fail "crowdsec should be down"
pidof crowdsec || fail "crowdsec process should be running"

#restart it
${SYSTEMCTL} restart crowdsec || fail "failed to stop service"
${SYSTEMCTL} status crowdsec || fail "crowdsec should be down"
pidof crowdsec || fail "crowdsec process should be running"




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
rm -rf ./test
## lapi
${CSCLI} lapi status || fail "lapi status failed"
## metrics
${CSCLI} metrics || fail "failed to get metrics"

${SYSTEMCTL} stop crowdsec || fail "crowdsec should be down"

## TEST WITHOUT LAPI
${CROWDSEC} -c ./config/config_no_lapi.yaml || fail "failed to run crowdsec without lapi (in configuration file)"
pidof crowdsec || fail "crowdsec process shouldn't be running"
pkill ${CROWDSEC}

${CROWDSEC} -no-api || fail "failed to run crowdsec without lapi (in flag)"
pidof crowdsec || fail "crowdsec should be running"
pkill ${CROWDSEC}

## capi
${CSCLI} capi status || fail "capi status should be ok"
## config
${CSCLI} config show || fail "failed to show config"
${CSCLI} config backup ./test || fail "failed to backup config"
rm -rf ./test
## lapi
${CSCLI} lapi status && fail "lapi status should not be ok" ## if lapi status success, it means that the test fail
## metrics
${CSCLI} metrics || fail "failed to get metrics"

## TEST WITHOUT AGENT
${CROWDSEC} -c ./config/config_no_agent.yaml || fail "failed to run crowdsec without lapi (in configuration file)"
pidof crowdsec || fail "crowdsec should be running"
pkill ${CROWDSEC}

${CROWDSEC} -no-agent || fail "failed to run crowdsec without lapi (in flag)"
pidof crowdsec || fail "crowdsec should be running"
pkill ${CROWDSEC}

## capi
${CSCLI} capi status || fail "capi status should be ok"
## config
${CSCLI} config show || fail "failed to show config"
${CSCLI} config backup ./test || fail "failed to backup config"
rm -rf ./test
## lapi
${CSCLI} lapi status || fail "lapi status failed"
## metrics
${CSCLI} metrics || fail "failed to get metrics"

## TEST WITHOUT CAPI
${CROWDSEC} -c ./config/config_no_capi.yaml || fail "failed to run crowdsec without lapi (in configuration file)"
pidof crowdsec || fail "crowdsec should be running"
pkill ${CROWDSEC}

## capi
${CSCLI} capi status && fail "capi status should not be ok" ## if capi status success, it means that the test fail
## config
${CSCLI} config show || fail "failed to show config"
${CSCLI} config backup ./test || fail "failed to backup config"
rm -rf ./test
## lapi
${CSCLI} lapi status || fail "lapi status failed"
## metrics
${CSCLI} metrics || fail "failed to get metrics"