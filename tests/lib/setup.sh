#!/usr/bin/env bash

# these plugins are always available

load "../lib/bats-support/load.bash"
load "../lib/bats-assert/load.bash"
#load "../lib/bats-file/load.bash"

# mark the start of each test in the logs, beware crowdsec might be running
# echo "time=\"$(date +"%d-%m-%Y %H:%M:%S")\" level=info msg=\"TEST: ${BATS_TEST_DESCRIPTION}\"" >> /var/log/crowdsec.log

export CROWDSEC_FEATURE_DISABLE_HTTP_RETRY_BACKOFF=true
