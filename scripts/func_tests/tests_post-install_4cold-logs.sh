#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh


# install sshd collection

${CSCLI} collections install crowdsecurity/sshd
${CSCLI} decisions delete --all
${SYSTEMCTL} reload crowdsec


# generate a fake bf log -> cold logs processing
rm  -f ssh-bf.log

sync

for i in `seq 1 6` ; do 
    echo `LC_ALL=C date '+%b %d %H:%M:%S '`'sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.172 port 35424' >> ssh-bf.log
done;

sync

${CROWDSEC} -dsn "file://./ssh-bf.log" -type syslog -no-api

${CSCLI} decisions list -o=json | ${JQ} '. | length == 1' || fail "expected exactly one decision"
${CSCLI} decisions list -o=json | ${JQ} '.[].decisions[0].value == "1.1.1.172"'  || fail "(exact) expected ban on 1.1.1.172"
${CSCLI} decisions list -r 1.1.1.0/24 -o=json --contained | ${JQ} '.[].decisions[0].value == "1.1.1.172"' || fail "(range/contained) expected ban on 1.1.1.172"
${CSCLI} decisions list -r 1.1.2.0/24 -o=json | ${JQ} '. == null'  || fail "(range/NOT-contained) expected no ban on 1.1.1.172"
${CSCLI} decisions list -i 1.1.1.172 -o=json | ${JQ} '.[].decisions[0].value == "1.1.1.172"'  || fail "(range/NOT-contained) expected ban on 1.1.1.172"
${CSCLI} decisions list -i 1.1.1.173 -o=json | ${JQ} '. == null' || fail "(exact) expected no ban on 1.1.1.173"

# generate a live ssh bf

${CSCLI} decisions delete --all

sudo cp /etc/crowdsec/acquis.yaml ./acquis.yaml.backup
echo "" | sudo tee -a /etc/crowdsec/acquis.yaml > /dev/null
echo "filename: /tmp/test.log" | sudo tee -a /etc/crowdsec/acquis.yaml > /dev/null
echo "labels:" | sudo tee -a /etc/crowdsec/acquis.yaml > /dev/null
echo "  type: syslog" | sudo tee -a /etc/crowdsec/acquis.yaml > /dev/null
touch /tmp/test.log

${SYSTEMCTL} restart crowdsec
wait_for_service "crowdsec should run (cold logs)"
${SYSTEMCTL} status crowdsec

sleep 2s

cat ssh-bf.log >> /tmp/test.log

sleep 5s
${CSCLI} decisions list -o=json | ${JQ} '.[].decisions[0].value == "1.1.1.172"' || fail "(live) expected ban on 1.1.1.172"

sudo cp ./acquis.yaml.backup /etc/crowdsec/acquis.yaml

sync

${SYSTEMCTL} restart crowdsec
wait_for_service "crowdsec should run"
