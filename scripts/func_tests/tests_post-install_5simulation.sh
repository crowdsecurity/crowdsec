#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh

COLLECTION=crowdsecurity/sshd
SCENARIO=crowdsecurity/ssh-bf

# install sshd collection

${CSCLI} collections install $COLLECTION
${CSCLI} decisions delete --all
${SYSTEMCTL} reload crowdsec


# generate a fake bf log -> cold logs processing
rm  -f ssh-bf.log

sync

# shellcheck disable=SC2034
for i in $(seq 1 10); do 
    echo "$(LC_ALL=C date '+%b %d %H:%M:%S') sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.174 port 35424" >> ssh-bf.log
done;

sync

${CROWDSEC} -dsn file://./ssh-bf.log -type syslog -no-api

sleep 1s

${CSCLI} decisions list -o=json | ${JQ} '. | length == 1' || fail "expected exactly one decision"
${CSCLI} decisions list -o=json | ${JQ} '.[].decisions[0].value == "1.1.1.174"'  || fail "(exact) expected ban on 1.1.1.174"
${CSCLI} decisions list -o=json | ${JQ} '.[].decisions[0].simulated == false'  || fail "(exact) expected simulated on false"


sleep 1s

# enable simulation on specific scenario and try with same logs

${CSCLI} decisions delete --all
${CSCLI} simulation enable $SCENARIO

${CROWDSEC} -dsn file://./ssh-bf.log -type syslog -no-api

${CSCLI} decisions list --no-simu -o=json | ${JQ} '. == null' || fail "expected no decision (listing only non-simulated decisions)"

sleep 1s
# enable global simulation and try with same logs

${CSCLI} decisions delete --all
${CSCLI} simulation disable $SCENARIO
${CSCLI} simulation enable --global

${CROWDSEC} -dsn file://./ssh-bf.log -type syslog -no-api

sleep 1s
${CSCLI} decisions list --no-simu -o=json | ${JQ} '. == null' || fail "expected no decision (listing only non-simulated decisions)"
