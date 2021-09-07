#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh

MOCK_SERVER_PID=""

function backup () {
    cat /etc/crowdsec/profiles.yaml > ./backup_profiles.yaml
    cat /etc/crowdsec/notifications/http.yaml > ./backup_http.yaml
}

function restore_backup () {
    cat ./backup_profiles.yaml > /etc/crowdsec/profiles.yaml  
    cat ./backup_http.yaml > /etc/crowdsec/notifications/http.yaml
}

function clear_backup() {
    rm ./backup_profiles.yaml
    rm ./backup_http.yaml
}

function modify_config() {
    sed -i 's,<HTTP_url>,http://localhost:9999,g' /etc/crowdsec/notifications/http.yaml
    echo "group_threshold: 2" >> /etc/crowdsec/notifications/http.yaml

    sed -i 's,Alert.Remediation == true && Alert.GetScope() == "Ip",1==1,g' /etc/crowdsec/profiles.yaml
    sed -i 's,# notifications,notifications,g' /etc/crowdsec/profiles.yaml
    sed -i 's,#   - http_default,   - http_default,g' /etc/crowdsec/profiles.yaml
    
    cat  /etc/crowdsec/profiles.yaml
    systemctl restart crowdsec
}

function setup_tests() {
    backup
    python3 -u mock_http_server.py > mock_http_server_logs.log &
    MOCK_SERVER_PID=$!
    modify_config
}

function cleanup_tests() {
    restore_backup
    clear_backup
    kill -9 $MOCK_SERVER_PID
    rm mock_http_server_logs.log
}

function run_tests() {
    log_line_count=$(cat mock_http_server_logs.log | wc -l)
    if [[ $log_line_count -ne "0" ]] ; then
        cleanup_tests
        fail "expected 0 log lines fom mock http server before adding decisions"
    fi

    cscli decisions add --ip 1.2.3.4 --duration 30s
    cscli decisions add --ip 1.2.3.5 --duration 30s
    sleep 5

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