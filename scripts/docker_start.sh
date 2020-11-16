#!/bin/sh
set -x
# Check if the container has already been started
cscli machines list | grep 127.0.0.1
if [ $? == 1 ]; then
    cscli machines add --force --auto -f /etc/crowdsec/local_api_credentials.yaml
fi

## Install collections, parsers & scenarios
cscli hub update
cscli collections upgrade crowdsecurity/linux
if [ "$COLLECTIONS" != "" ]; then
    cscli collections install $COLLECTIONS
fi
if [ "$PARSERS" != "" ]; then
    cscli parsers install $PARSERS
fi
if [ "$SCENARIOS" != "" ]; then
    cscli scenarios install $SCENARIOS
fi
if [ "$POSTOVERFLOWS" != "" ]; then
    cscli postoverflows install $POSTOVERFLOWS
fi

exec crowdsec -c /etc/crowdsec/config.yaml