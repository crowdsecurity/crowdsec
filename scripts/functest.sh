#! /usr/bin/env bash
# -*- coding: utf-8 -*-

CSCLI_BIN="./cscli"
CSCLI="${CSCLI_BIN} -c dev.yaml"
JQ="jq -e"
HTTP_URI="http://localhost:8081"


function fail
{
    echo "test failure !"
    caller 0
    exit 1
}

function init
{
    killall crowdsec
    rm data/crowdsec.db
    ${CSCLI} machines add -a
    ./crowdsec -c dev.yaml> crowdsec-out.log 2>&1  &
    sleep 1

}


function docurl
{
    APIK=$1
    URI=$2
    curl -s -H "X-Api-Key: ${APIK}" "http://localhost:8081${URI}"
} 

###
### ipv4 tests
###

init
APIK=`${CSCLI} bouncers add TestingBouncer -o=raw`

#
# ip ipv4 tests
#
${CSCLI} decisions list -o json | ${JQ} '. == null' || fail
docurl ${APIK} /v1/decisions | ${JQ} '. == null' || fail
#add ip decision
${CSCLI} decisions add -i 1.2.3.4  || fail
${CSCLI} decisions list -o json | ${JQ} '.[].decisions[0].value == "1.2.3.4"'  || fail
docurl ${APIK} /v1/decisions | ${JQ} '.[0].value == "1.2.3.4"' || fail
#check ip match
${CSCLI} decisions list -i 1.2.3.4 -o json | ${JQ} '.[].decisions[0].value == "1.2.3.4"'  || fail
docurl ${APIK} /v1/decisions?ip=1.2.3.4 | ${JQ} '.[0].value == "1.2.3.4"' || fail
${CSCLI} decisions list -i 1.2.3.5 -o json | ${JQ} '. == null'  || fail
docurl ${APIK} /v1/decisions?ip=1.2.3.4 | ${JQ} '. == null' || fail
#check outer range match
${CSCLI} decisions list -r 1.2.3.0/24 -o json | ${JQ} '. == null'  || fail
docurl ${APIK} "/v1/decisions?range=1.2.3.0/24" | ${JQ} '. == null' || fail
${CSCLI} decisions list -r 1.2.3.0/24 --contained -o json |${JQ} '.[].decisions[0].value == "1.2.3.4"'  || fail
docurl ${APIK} "/v1/decisions?range=1.2.3.0/24&contains=false" | ${JQ} '.[0].value == "1.2.3.4"' || fail
#
# range ipv4 tests
#
#add range decision
${CSCLI} decisions add -r 4.4.4.0/24 || fail
${CSCLI} decisions list -o json | ${JQ} '.[0].decisions[0].value == "4.4.4.0/24", .[1].decisions[0].value == "1.2.3.4"' || fail
docurl ${APIK} "/v1/decisions" | ${JQ} '.[0].value == "4.4.4.0/24", .[1].value == "1.2.3.4"' || fail

#check ip within/outside of range
${CSCLI} decisions list -i 4.4.4.3 -o json | ${JQ} '.[].decisions[0].value == "4.4.4.0/24"'  || fail
${CSCLI} decisions list -i 4.4.4.4 -o json --contained | ${JQ} '. == null' || fail
${CSCLI} decisions list -i 5.4.4.3 -o json | ${JQ} '. == null'  || fail
#check outer range
${CSCLI} decisions list -r 4.4.0.0/16 -o json | ${JQ} '. == null'  || fail
${CSCLI} decisions list -r 4.4.0.0/16 -o json --contained | ${JQ} '.[].decisions[0].value == "4.4.4.0/24"'  || fail
#check subrange
${CSCLI} decisions list -r 4.4.4.2/28 -o json | ${JQ} '.[].decisions[0].value == "4.4.4.0/24"'  || fail
${CSCLI} decisions list -r 4.4.3.2/28 -o json | ${JQ} '. == null'  || fail

###
### ipv6 tests
###
init
APIK=`${CSCLI} bouncers add TestingBouncer -o=raw`

#
# ip ipv6 tests
#
#add ip decision
${CSCLI} decisions add -i 1111:2222:3333:4444:5555:6666:7777:8888
${CSCLI} decisions list -o json | jq -e '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"'  || fail
#check ip matching/unmatching
${CSCLI} decisions list -i 1111:2222:3333:4444:5555:6666:7777:8888 -o json | jq -e '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"'  || fail
${CSCLI} decisions list -i 1211:2222:3333:4444:5555:6666:7777:8888 -o json | jq -e '. == null' || fail
${CSCLI} decisions list -i 1111:2222:3333:4444:5555:6666:7777:8887 -o json | jq -e '. == null' || fail
#check outer range
${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/48 -o json | jq -e '. == null' || fail
${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/48 --contained -o json | jq -e '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"' || fail
${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/64 -o json | jq -e '. == null' || fail
${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/64 -o json --contained | jq -e '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"'  || fail
#
# range ipv6 test
#
#add range decision
${CSCLI} decisions add -r aaaa:2222:3333:4444::/64
${CSCLI} decisions list -o json | jq -e '.[0].decisions[0].value == "aaaa:2222:3333:4444::/64", .[1].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"' || fail
#check ip within/out of range
${CSCLI} decisions list -i aaaa:2222:3333:4444:5555:6666:7777:8888 -o json | jq -e '.[].decisions[0].value == "aaaa:2222:3333:4444::/64"'  || fail
${CSCLI} decisions list -i aaaa:2222:3333:4445:5555:6666:7777:8888 -o json | jq -e '. == null' || fail
${CSCLI} decisions list -i aaa1:2222:3333:4444:5555:6666:7777:8887 -o json | jq -e '. == null' || fail
#check subrange within/out of range
${CSCLI} decisions list -r aaaa:2222:3333:4444:5555::/80 -o json | jq -e '.[].decisions[0].value == "aaaa:2222:3333:4444::/64"'  || fail
${CSCLI} decisions list -r aaaa:2222:3333:4441:5555::/80 -o json | jq -e '. == null'  || fail
${CSCLI} decisions list -r aaa1:2222:3333:4444:5555::/80 -o json | jq -e '. == null'  || fail
#check outer range
${CSCLI} decisions list -r aaaa:2222:3333:4444:5555:6666:7777:8888/48 -o json | jq -e '. == null' || fail
${CSCLI} decisions list -r aaaa:2222:3333:4444:5555:6666:7777:8888/48 -o json --contained | jq -e '.[].decisions[0].value == "aaaa:2222:3333:4444::/64"' || fail


##
## Bouncers tests
##
