#! /usr/bin/env bash
# -*- coding: utf-8 -*-


source tests_base.sh


# Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
OK_STR="${GREEN}OK${NC}"
FAIL_STR="${RED}FAIL${NC}"


CROWDSEC_API_URL="http://localhost:8081"
API_KEY=""

FAILED="false"
MUST_FAIL="false"

### Helpers
function docurl
{
    URI=$1
    curl -s -H "X-Api-Key: ${API_KEY}" "${CROWDSEC_API_URL}${URI}"
} 

function bouncer_echo {
    if [[ ${FAILED} == "false" ]];
    then
        echo -e "[bouncer] $1: ${OK_STR}"
    else
        echo -e "[bouncer] $1: ${FAIL_STR}"
    fi
    FAILED="false"
}

function cscli_echo {
    if [[ ${FAILED} == "false" ]];
    then
        echo -e "[cscli]   $1: ${OK_STR}"
    else
        echo -e "[cscli]   $1: ${FAIL_STR}"
    fi
    FAILED="false"
}

function test_ipv4_ip
{
    echo ""
    echo "##########################################"
    echo "$FUNCNAME"
    echo "##########################################"
    echo ""
    
    ${CSCLI} decisions list -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "first decisions list"
    
    docurl /v1/decisions | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "first bouncer decisions request (must be empty)"

    #add ip decision
    echo "adding decision for 1.2.3.4"
    ${CSCLI} decisions add -i 1.2.3.4  > /dev/null 2>&1 || fail
    
    ${CSCLI} decisions list -o json | ${JQ} '.[].decisions[0].value == "1.2.3.4"' > /dev/null || fail
    cscli_echo "getting all decision"
    
    docurl /v1/decisions | ${JQ} '.[0].value == "1.2.3.4"' > /dev/null || fail
    bouncer_echo "getting all decision"

    #check ip match
    ${CSCLI} decisions list -i 1.2.3.4 -o json | ${JQ} '.[].decisions[0].value == "1.2.3.4"'  > /dev/null || fail
    cscli_echo "getting decision for 1.2.3.4"
    
    docurl /v1/decisions?ip=1.2.3.4 | ${JQ} '.[0].value == "1.2.3.4"' > /dev/null || fail
    bouncer_echo "getting decision for 1.2.3.4"

    ${CSCLI} decisions list -i 1.2.3.5 -o json | ${JQ} '. == null'  > /dev/null || fail
    cscli_echo "getting decision for 1.2.3.5"

    docurl /v1/decisions?ip=1.2.3.5 | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decision for 1.2.3.5"

    #check outer range match
    ${CSCLI} decisions list -r 1.2.3.0/24 -o json | ${JQ} '. == null'  > /dev/null || fail
    cscli_echo "getting decision for 1.2.3.0/24"

    docurl "/v1/decisions?range=1.2.3.0/24" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decision for 1.2.3.0/24"

    ${CSCLI} decisions list -r 1.2.3.0/24 --contained -o json |${JQ} '.[].decisions[0].value == "1.2.3.4"'  > /dev/null || fail
    cscli_echo "getting decisions where IP in 1.2.3.0/24"

    docurl "/v1/decisions?range=1.2.3.0/24&contains=false" | ${JQ} '.[0].value == "1.2.3.4"' > /dev/null || fail
    bouncer_echo "getting decisions where IP in 1.2.3.0/24"

}

function test_ipv4_range
{
    echo ""
    echo "##########################################"
    echo "$FUNCNAME"
    echo "##########################################"
    echo ""


    cscli_echo "adding decision for range 4.4.4.0/24"
    ${CSCLI} decisions add -r 4.4.4.0/24 > /dev/null 2>&1 || fail

    ${CSCLI} decisions list -o json | ${JQ} '.[0].decisions[0].value == "4.4.4.0/24", .[1].decisions[0].value == "1.2.3.4"'> /dev/null || fail
    cscli_echo "getting all decision"
    
    docurl "${APIK}" "/v1/decisions" | ${JQ} '.[0].value == "1.2.3.4", .[1].value == "4.4.4.0/24"'> /dev/null || fail
    bouncer_echo "getting all decision"

    #check ip within/outside of range
    ${CSCLI} decisions list -i 4.4.4.3 -o json | ${JQ} '.[].decisions[0].value == "4.4.4.0/24"' > /dev/null || fail
    cscli_echo "getting decisions for ip 4.4.4."

    docurl "${APIK}" "/v1/decisions?ip=4.4.4.3" | ${JQ} '.[0].value == "4.4.4.0/24"' > /dev/null || fail
    bouncer_echo "getting decisions for ip 4.4.4."

    ${CSCLI} decisions list -i 4.4.4.4 -o json --contained | ${JQ} '. == null'> /dev/null || fail
    cscli_echo "getting decisions for ip contained in 4.4.4."

    docurl "${APIK}" "/v1/decisions?ip=4.4.4.4&contains=false" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip contained in 4.4.4."

    ${CSCLI} decisions list -i 5.4.4.3 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip 5.4.4."

    docurl "${APIK}" "/v1/decisions?ip=5.4.4.3" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip 5.4.4."

    ${CSCLI} decisions list -r 4.4.0.0/16 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for range 4.4.0.0/1"

    docurl "${APIK}" "/v1/decisions?range=4.4.0.0/16" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for range 4.4.0.0/1"

    ${CSCLI} decisions list -r 4.4.0.0/16 -o json --contained | ${JQ} '.[].decisions[0].value == "4.4.4.0/24"' > /dev/null || fail
    cscli_echo "getting decisions for ip/range in 4.4.0.0/1"

    docurl "${APIK}" "/v1/decisions?range=4.4.0.0/16&contains=false" | ${JQ} '.[0].value == "4.4.4.0/24"' > /dev/null || fail
    bouncer_echo "getting decisions for ip/range in 4.4.0.0/1"

    #check subrange
    ${CSCLI} decisions list -r 4.4.4.2/28 -o json | ${JQ} '.[].decisions[0].value == "4.4.4.0/24"' > /dev/null || fail
    cscli_echo "getting decisions for range 4.4.4.2/2"

    docurl "${APIK}" "/v1/decisions?range=4.4.4.2/28" | ${JQ} '.[].value == "4.4.4.0/24"' > /dev/null || fail
    bouncer_echo "getting decisions for range 4.4.4.2/2"

    ${CSCLI} decisions list -r 4.4.3.2/28 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for range 4.4.3.2/2"

    docurl "${APIK}" "/v1/decisions?range=4.4.3.2/28" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for range 4.4.3.2/2"

}

function test_ipv6_ip
{

    echo ""
    echo "##########################################"
    echo "$FUNCNAME"
    echo "##########################################"
    echo ""

    cscli_echo "adding decision for ip 1111:2222:3333:4444:5555:6666:7777:8888"
    ${CSCLI} decisions add -i 1111:2222:3333:4444:5555:6666:7777:8888 > /dev/null 2>&1

    ${CSCLI} decisions list -o json | ${JQ} '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"'  > /dev/null || fail
    cscli_echo "getting all decision"

    docurl "${APIK}" "/v1/decisions" | ${JQ} '.[].value == "1111:2222:3333:4444:5555:6666:7777:8888"' > /dev/null || fail
    bouncer_echo "getting all decision"

    ${CSCLI} decisions list -i 1111:2222:3333:4444:5555:6666:7777:8888 -o json | ${JQ} '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"'  > /dev/null || fail
    cscli_echo "getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:8888"
    
    docurl "${APIK}" "/v1/decisions?ip=1111:2222:3333:4444:5555:6666:7777:8888" | ${JQ} '.[].value == "1111:2222:3333:4444:5555:6666:7777:8888"' > /dev/null || fail
    bouncer_echo "getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:888"

    ${CSCLI} decisions list -i 1211:2222:3333:4444:5555:6666:7777:8888 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip 1211:2222:3333:4444:5555:6666:7777:8888"

    docurl "${APIK}" "/v1/decisions?ip=1211:2222:3333:4444:5555:6666:7777:8888" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip 1211:2222:3333:4444:5555:6666:7777:888"

    ${CSCLI} decisions list -i 1111:2222:3333:4444:5555:6666:7777:8887 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:8887"

    docurl "${APIK}" "/v1/decisions?ip=1111:2222:3333:4444:5555:6666:7777:8887" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:888"

    ${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/48 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/48"

    docurl "${APIK}" "/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/48" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/48"

    ${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/48 --contained -o json | ${JQ} '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"' > /dev/null || fail
    cscli_echo "getting decisions for ip/range in range 1111:2222:3333:4444:5555:6666:7777:8888/48"

    docurl "${APIK}" "/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/48&&contains=false" | ${JQ} '.[].value == "1111:2222:3333:4444:5555:6666:7777:8888"' > /dev/null || fail
    bouncer_echo "getting decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/48"

    ${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/64 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/64"

    docurl "${APIK}" "/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/64" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for range 1111:2222:3333:4444:5555:6666:7777:8888/64"

    ${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/64 -o json --contained | ${JQ} '.[].decisions[0].value == "1111:2222:3333:4444:5555:6666:7777:8888"'  > /dev/null || fail
    cscli_echo "getting decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64"

    docurl "${APIK}" "/v1/decisions?range=1111:2222:3333:4444:5555:6666:7777:8888/64&&contains=false" | ${JQ} '.[].value == "1111:2222:3333:4444:5555:6666:7777:8888"' > /dev/null || fail
    bouncer_echo "getting decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64"

    cscli_echo "adding decision for ip 1111:2222:3333:4444:5555:6666:7777:8889"
    ${CSCLI} decisions add -i 1111:2222:3333:4444:5555:6666:7777:8889 > /dev/null 2>&1

    cscli_echo "deleting decision for ip 1111:2222:3333:4444:5555:6666:7777:8889"
    ${CSCLI} decisions delete -i 1111:2222:3333:4444:5555:6666:7777:8889

    ${CSCLI} decisions list -i 1111:2222:3333:4444:5555:6666:7777:8889 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip 1111:2222:3333:4444:5555:6666:7777:8889 after delete"

    cscli_echo "deleting decision for range 1111:2222:3333:4444:5555:6666:7777:8888/64"
    ${CSCLI} decisions delete -r 1111:2222:3333:4444:5555:6666:7777:8888/64 --contained

    ${CSCLI} decisions list -r 1111:2222:3333:4444:5555:6666:7777:8888/64 -o json --contained | ${JQ} '. == null'  > /dev/null || fail
    cscli_echo "getting decisions for ip/range in 1111:2222:3333:4444:5555:6666:7777:8888/64 after delete"
}

function test_ipv6_range
{
    echo ""
    echo "##########################################"
    echo "$FUNCNAME"
    echo "##########################################"
    echo ""

    cscli_echo "adding decision for range aaaa:2222:3333:4444::/64"
    ${CSCLI} decisions add -r aaaa:2222:3333:4444::/64 > /dev/null 2>&1 || fail
     
    ${CSCLI} decisions list -o json | ${JQ} '.[0].decisions[0].value == "aaaa:2222:3333:4444::/64"' > /dev/null || fail
    cscli_echo "getting all decision"

    docurl "${APIK}" "/v1/decisions" | ${JQ} '.[0].value == "aaaa:2222:3333:4444::/64"' > /dev/null || fail
    bouncer_echo "getting all decision"

    #check ip within/out of range
    ${CSCLI} decisions list -i aaaa:2222:3333:4444:5555:6666:7777:8888 -o json | ${JQ} '.[].decisions[0].value == "aaaa:2222:3333:4444::/64"'  > /dev/null || fail
    cscli_echo "getting decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888"

    docurl "${APIK}" "/v1/decisions?ip=aaaa:2222:3333:4444:5555:6666:7777:8888" | ${JQ} '.[].value == "aaaa:2222:3333:4444::/64"' > /dev/null || fail
    bouncer_echo "getting decisions for ip aaaa:2222:3333:4444:5555:6666:7777:8888"

    ${CSCLI} decisions list -i aaaa:2222:3333:4445:5555:6666:7777:8888 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888"

    docurl "${APIK}" "/v1/decisions?ip=aaaa:2222:3333:4445:5555:6666:7777:8888" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip aaaa:2222:3333:4445:5555:6666:7777:8888"

    ${CSCLI} decisions list -i aaa1:2222:3333:4444:5555:6666:7777:8887 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887"

    docurl "${APIK}" "/v1/decisions?ip=aaa1:2222:3333:4444:5555:6666:7777:8887" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip aaa1:2222:3333:4444:5555:6666:7777:8887"

    #check subrange within/out of range
    ${CSCLI} decisions list -r aaaa:2222:3333:4444:5555::/80 -o json | ${JQ} '.[].decisions[0].value == "aaaa:2222:3333:4444::/64"'  > /dev/null || fail
    cscli_echo "getting decisions for range aaaa:2222:3333:4444:5555::/80"
    
    docurl "${APIK}" "/v1/decisions?range=aaaa:2222:3333:4444:5555::/80" | ${JQ} '.[].value == "aaaa:2222:3333:4444::/64"' > /dev/null || fail
    bouncer_echo "getting decisions for range aaaa:2222:3333:4444:5555::/80"

    ${CSCLI} decisions list -r aaaa:2222:3333:4441:5555::/80 -o json | ${JQ} '. == null'  > /dev/null || fail
    cscli_echo "getting decisions for range aaaa:2222:3333:4441:5555::/80"
    
    docurl "${APIK}" "/v1/decisions?range=aaaa:2222:3333:4441:5555::/80" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for range aaaa:2222:3333:4441:5555::/80"

    ${CSCLI} decisions list -r aaa1:2222:3333:4444:5555::/80 -o json | ${JQ} '. == null'  > /dev/null || fail
    cscli_echo "getting decisions for range aaa1:2222:3333:4444:5555::/80"

    docurl "${APIK}" "/v1/decisions?range=aaa1:2222:3333:4444:5555::/80" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for range aaa1:2222:3333:4444:5555::/80"

    #check outer range
    ${CSCLI} decisions list -r aaaa:2222:3333:4444:5555:6666:7777:8888/48 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48"

    docurl "${APIK}" "/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for range aaaa:2222:3333:4444:5555:6666:7777:8888/48"

    ${CSCLI} decisions list -r aaaa:2222:3333:4444:5555:6666:7777:8888/48 -o json --contained | ${JQ} '.[].decisions[0].value == "aaaa:2222:3333:4444::/64"' > /dev/null || fail
    cscli_echo "getting decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48"

    docurl "${APIK}" "/v1/decisions?range=aaaa:2222:3333:4444:5555:6666:7777:8888/48&contains=false" | ${JQ} '.[].value == "aaaa:2222:3333:4444::/64"' > /dev/null || fail
    bouncer_echo "getting decisions for ip/range in aaaa:2222:3333:4444:5555:6666:7777:8888/48"

    ${CSCLI} decisions list -r aaaa:2222:3333:4445:5555:6666:7777:8888/48 -o json | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip/range aaaa:2222:3333:4445:5555:6666:7777:8888/48"

    docurl "${APIK}" "/v1/decisions?range=aaaa:2222:3333:4445:5555:6666:7777:8888/48" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip/range in aaaa:2222:3333:4445:5555:6666:7777:8888/48"

    #bbbb:db8:: -> bbbb:db8:0000:0000:0000:7fff:ffff:ffff
    ${CSCLI} decisions add -r bbbb:db8::/81 > /dev/null 2>&1
    cscli_echo "adding decision for range bbbb:db8::/81" > /dev/null || fail

    ${CSCLI} decisions list -o json -i bbbb:db8:0000:0000:0000:6fff:ffff:ffff | ${JQ} '.[].decisions[0].value == "bbbb:db8::/81"'  > /dev/null || fail
    cscli_echo "getting decisions for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff"
    
    docurl "${APIK}" "/v1/decisions?ip=bbbb:db8:0000:0000:0000:6fff:ffff:ffff" | ${JQ} '.[].value == "bbbb:db8::/81"' > /dev/null || fail
    bouncer_echo "getting decisions for ip in bbbb:db8:0000:0000:0000:6fff:ffff:ffff"

    ${CSCLI} decisions list -o json -i bbbb:db8:0000:0000:0000:8fff:ffff:ffff | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff"

    docurl "${APIK}" "/v1/decisions?ip=bbbb:db8:0000:0000:0000:8fff:ffff:ffff" | ${JQ} '. == null' > /dev/null || fail
    bouncer_echo "getting decisions for ip in bbbb:db8:0000:0000:0000:8fff:ffff:ffff"

    cscli_echo "deleting decision for range aaaa:2222:3333:4444:5555:6666:7777:8888/48"
    ${CSCLI} decisions delete -r aaaa:2222:3333:4444:5555:6666:7777:8888/48 --contained > /dev/null 2>&1 || fail
    
    ${CSCLI} decisions list -o json -r aaaa:2222:3333:4444::/64 | ${JQ} '. == null' > /dev/null || fail
    cscli_echo "getting decisions for range aaaa:2222:3333:4444::/64 after delete"

    cscli_echo "adding decision for ip bbbb:db8:0000:0000:0000:8fff:ffff:ffff"
    ${CSCLI} decisions add -i bbbb:db8:0000:0000:0000:8fff:ffff:ffff > /dev/null 2>&1 || fail
    cscli_echo "adding decision for ip bbbb:db8:0000:0000:0000:6fff:ffff:ffff"
    ${CSCLI} decisions add -i bbbb:db8:0000:0000:0000:6fff:ffff:ffff > /dev/null 2>&1 || fail

    cscli_echo "deleting decision for range bbbb:db8::/81"
    ${CSCLI} decisions delete -r bbbb:db8::/81 --contained > /dev/null 2>&1 || fail
    
    ${CSCLI} decisions list -o json | ${JQ} '.[].decisions[0].value == "bbbb:db8:0000:0000:0000:8fff:ffff:ffff"' > /dev/null || fail
    cscli_echo "getting all decisions"

}


function start_test
{

    ## ipv4 testing
    ${CSCLI} decisions delete --all

    test_ipv4_ip
    test_ipv4_range

    ## ipv6 testing
    ${CSCLI} decisions delete --all
    test_ipv6_ip
    test_ipv6_range
}


usage() {
      echo "Usage:"
      echo ""
      echo "    ./ip_mgmt_tests.sh -h                                   Display this help message."
      echo "    ./ip_mgmt_tests.sh                                      Run all the testsuite. Go must be available to make the release"
      echo "    ./ip_mgmt_tests.sh --release <path_to_release_folder>   If go is not installed, please provide a path to the crowdsec-vX.Y.Z release folder"
      echo ""
      exit 0  
}

while [[ $# -gt 0 ]]
do
    key="${1}"
    case ${key} in
    --release|-r)
        RELEASE_FOLDER="${2}"
        shift #past argument
        shift
        ;;   
    -h|--help)
        usage
        exit 0
        ;;
    *)    # unknown option
        echo "Unknown argument ${key}."
        usage
        exit 1
        ;;
    esac
done


start_test

if [[ "${MUST_FAIL}" == "true" ]];
then
    echo ""
    echo "One or more tests have failed !"
    exit 1
fi
