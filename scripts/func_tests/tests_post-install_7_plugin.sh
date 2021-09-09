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
    cat ./config/http.yaml | sudo tee /etc/crowdsec/notifications/http.yaml > /dev/null
    cat ./config/profiles.yaml | sudo tee /etc/crowdsec/profiles.yaml > /dev/null
    ${SYSTEMCTL} restart crowdsec
}

function setup_tests() {
    backup
    cscli decisions delete --all
    modify_config
    python3 -u mock_http_server.py > mock_http_server_logs.log &
    MOCK_SERVER_PID=$!
}

function cleanup_tests() {
    restore_backup
    clear_backup
    kill -9 $MOCK_SERVER_PID
    rm mock_http_server_logs.log
    ${SYSTEMCTL} restart crowdsec
}

function run_tests() {
    log_line_count=$(cat mock_http_server_logs.log | wc -l)
    if [[ $log_line_count -ne "0" ]] ; then
        cleanup_tests
        fail "expected 0 log lines fom mock http server before adding decisions"
    fi
    ${CSCLI} decisions add --ip 1.2.3.4 --duration 30s
    ${CSCLI} decisions add --ip 1.2.3.5 --duration 30s
    sleep 5
    cat mock_http_server_logs.log
    log_line_count=$(cat mock_http_server_logs.log | wc -l)
    if [[ $log_line_count -ne "1" ]] ; then
        cleanup_tests
        fail "expected 1 log line from http server"
    fi

    total_alerts=$(cat mock_http_server_logs.log   | jq  .request_body | jq length)
    if [[ $total_alerts -ne "2" ]] ; then
        cleanup_tests
        fail "expected to receive 2 alerts in the request body from plugin"
    fi

    first_received_ip=$(cat mock_http_server_logs.log  | jq -r .request_body[0].decisions[0].value)
    if [[ $first_received_ip != "1.2.3.4" ]] ; then
        cleanup_tests
        fail "expected to receive IP 1.2.3.4 as value of first decision"
    fi 

    second_received_ip=$(cat mock_http_server_logs.log  | jq -r .request_body[1].decisions[0].value)
    if [[ $second_received_ip != "1.2.3.5" ]] ; then
        cleanup_tests
        fail "expected to receive IP 1.2.3.5 as value of second decision"
    fi 
}

setup_tests
run_tests
cleanup_tests
