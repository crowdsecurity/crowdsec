#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh



##########################
## TEST AGENT/LAPI/CAPI ##
echo "CROWDSEC (AGENT+LAPI+CAPI)"

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
sudo rm -rf ./test
## lapi
${CSCLI} lapi status || fail "lapi status failed"
## metrics
${CSCLI} metrics || fail "failed to get metrics"

${SYSTEMCTL} stop crowdsec || fail "crowdsec should be down"

#######################
## TEST WITHOUT LAPI ##

echo "CROWDSEC (AGENT)"

# test with -no-api flag
sudo cp ./systemd/crowdsec_no_lapi.service /etc/systemd/system/crowdsec.service
${SYSTEMCTL} daemon-reload
${SYSTEMCTL} start crowdsec
sleep 1
pidof crowdsec && fail "crowdsec shouldn't run without LAPI (in flag)"
${SYSTEMCTL} stop crowdsec

sudo cp ./systemd/crowdsec.service /etc/systemd/system/crowdsec.service
${SYSTEMCTL} daemon-reload

# test with no api server in configuration file
sudo cp ./config/config_no_lapi.yaml /etc/crowdsec/config.yaml
${SYSTEMCTL} start crowdsec
sleep 1
pidof crowdsec && fail "crowdsec agent should not run without lapi (in configuration file)"

##### cscli test ####
## capi
${CSCLI} -c ./config/config_no_lapi.yaml capi status && fail "capi status shouldn't be ok"
## config
${CSCLI_BIN} -c ./config/config_no_lapi.yaml config show || fail "failed to show config"
${CSCLI} -c ./config/config_no_lapi.yaml config backup ./test || fail "failed to backup config"
sudo rm -rf ./test
## lapi
${CSCLI} -c ./config/config_no_lapi.yaml lapi status && fail "lapi status should not be ok" ## if lapi status success, it means that the test fail
## metrics
${CSCLI_BIN} -c ./config/config_no_lapi.yaml metrics

${SYSTEMCTL} stop crowdsec
sudo cp ./config/config.yaml /etc/crowdsec/config.yaml

########################
## TEST WITHOUT AGENT ##

echo "CROWDSEC (LAPI+CAPI)"

# test with -no-cs flag
sudo cp ./systemd/crowdsec_no_agent.service /etc/systemd/system/crowdsec.service
${SYSTEMCTL} daemon-reload
${SYSTEMCTL} start crowdsec 
pidof crowdsec || fail "crowdsec LAPI should run without agent (in flag)"
${SYSTEMCTL} stop crowdsec

sudo cp ./systemd/crowdsec.service /etc/systemd/system/crowdsec.service
${SYSTEMCTL} daemon-reload

# test with no crowdsec agent in configuration file
sudo cp ./config/config_no_agent.yaml /etc/crowdsec/config.yaml
${SYSTEMCTL} start crowdsec 
pidof crowdsec || fail "crowdsec LAPI should run without agent (in configuration file)"


## capi
${CSCLI} -c ./config/config_no_agent.yaml capi status || fail "capi status should be ok"
## config
${CSCLI_BIN} -c ./config/config_no_agent.yaml config show || fail "failed to show config"
${CSCLI} -c ./config/config_no_agent.yaml config backup ./test || fail "failed to backup config"
sudo rm -rf ./test
## lapi
${CSCLI} -c ./config/config_no_agent.yaml lapi status || fail "lapi status failed"
## metrics
${CSCLI_BIN} -c ./config/config_no_agent.yaml metrics || fail "failed to get metrics"

${SYSTEMCTL} stop crowdsec
sudo cp ./config/config.yaml /etc/crowdsec/config.yaml


#######################
## TEST WITHOUT CAPI ##
echo "CROWDSEC (AGENT+LAPI)"

# test with no online client in configuration file
sudo cp ./config/config_no_capi.yaml /etc/crowdsec/config.yaml
${SYSTEMCTL} start crowdsec 
pidof crowdsec || fail "crowdsec LAPI should run without CAPI (in configuration file)"

## capi
${CSCLI} -c ./config/config_no_capi.yaml capi status && fail "capi status should not be ok" ## if capi status success, it means that the test fail
## config
${CSCLI_BIN} -c ./config/config_no_capi.yaml config show || fail "failed to show config"
${CSCLI} -c ./config/config_no_capi.yaml config backup ./test || fail "failed to backup config"
sudo rm -rf ./test
## lapi
${CSCLI} -c ./config/config_no_capi.yaml lapi status || fail "lapi status failed"
## metrics
${CSCLI_BIN} -c ./config/config_no_capi.yaml metrics || fail "failed to get metrics"

sudo cp ./config/config.yaml /etc/crowdsec/config.yaml
${SYSTEMCTL} restart crowdsec
