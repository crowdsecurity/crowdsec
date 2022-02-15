#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh

MOCK_SERVER_PID=""

function backup () {
    cat /etc/crowdsec/profiles.yaml > ./backup_profiles.yaml
    cat /etc/crowdsec/notifications/http.yaml > ./backup_http.yaml
}

function restore_backup () {
    cat ./backup_profiles.yaml | sudo tee /etc/crowdsec/profiles.yaml > /dev/null
    cat ./backup_http.yaml | sudo tee /etc/crowdsec/notifications/http.yaml > /dev/null
}

function clear_backup() {
    rm ./backup_profiles.yaml
    rm ./backup_http.yaml
}

function modify_config() {
    PLUGINS_DIR=$(sudo find /usr -type d -wholename "*"crowdsec/plugins)
    sed -i "s#/usr/local/lib/crowdsec/plugins#${PLUGINS_DIR}#g" ./config/config.yaml
    cat ./config/config.yaml | sed 's/group: nogroup/group: '$(groups nobody | cut -d ':' -f2 | tr -d ' ')'/' | sudo tee /etc/crowdsec/config.yaml > /dev/null
    cat ./config/http.yaml | sudo tee /etc/crowdsec/notifications/http.yaml > /dev/null
    cat ./config/profiles.yaml | sudo tee /etc/crowdsec/profiles.yaml > /dev/null
    
    ${SYSTEMCTL} restart crowdsec
    sleep 5s
}

function setup_tests() {
    backup
    cscli decisions delete --all
    modify_config
    python3 -u mock_http_server.py > mock_http_server_logs.log &
    count=0
    while ! nc -z localhost 9999; do   
        sleep 0.5
        ((count ++))
        if [[ $count == 41 ]]; then
            fail "mock server not up after 20s"
        fi
    done

    MOCK_SERVER_PID=$!
}

function cleanup_tests() {
    restore_backup
    clear_backup
    kill -9 $MOCK_SERVER_PID
    rm mock_http_server_logs.log
    ${SYSTEMCTL} restart crowdsec
    sleep 5s
}

function run_tests() {
    log_line_count=$(wc -l <mock_http_server_logs.log)

    if [[ $log_line_count -ne "0" ]] ; then
        cleanup_tests
        fail "expected 0 log lines fom mock http server before adding decisions"
    fi
    sleep 5s
    ${CSCLI} decisions add --ip 1.2.3.4 --duration 30s
    ${CSCLI} decisions add --ip 1.2.3.5 --duration 30s
    sleep 5s
    cat mock_http_server_logs.log
    log_line_count=$(wc -l <mock_http_server_logs.log)
    if [[ $log_line_count -ne "1" ]] ; then
        cleanup_tests
        fail "expected 1 log line from http server"
    fi

    total_alerts=$(jq <mock_http_server_logs.log .request_body | jq length)
    if [[ $total_alerts -ne "2" ]] ; then
        cleanup_tests
        fail "expected to receive 2 alerts in the request body from plugin"
    fi

    first_received_ip=$(jq <mock_http_server_logs.log -r .request_body[0].decisions[0].value)
    if [[ $first_received_ip != "1.2.3.4" ]] ; then
        cleanup_tests
        fail "expected to receive IP 1.2.3.4 as value of first decision"
    fi 

    second_received_ip=$(jq <mock_http_server_logs.log -r .request_body[1].decisions[0].value)
    if [[ $second_received_ip != "1.2.3.5" ]] ; then
        cleanup_tests
        fail "expected to receive IP 1.2.3.5 as value of second decision"
    fi 
}

setup_tests
run_tests
cleanup_tests

