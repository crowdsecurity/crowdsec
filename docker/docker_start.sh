#!/bin/sh

# Check if the container has already been started
cscli machines list | grep 127.0.0.1
if [ $? == 1 ]; then
    cscli machines add --force --auto -f /etc/crowdsec/local_api_credentials.yaml
fi

if [ "$REGISTER_TO_ONLINE_API" == "true" ] || [ "$REGISTER_TO_ONLINE_API" == "TRUE" ] && [ "$CONFIG_FILE" == "" ] ; then
    cat /etc/crowdsec/config.yaml | grep online_api_credentials.yaml
    if [ $? == 1 ]; then
        sed -ri 's/^(\s*)(#credentials_path\s*:\s*$)/\1credentials_path: \/etc\/crowdsec\/online_api_credentials.yaml/' /etc/crowdsec/config.yaml
        cscli capi register > /etc/crowdsec/online_api_credentials.yaml
    fi
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

ARGS=""
if [ "$CONFIG_FILE" != "" ]; then
    ARGS="-c $CONFIG_FILE"
fi
if [ "$FILE_PATH" != "" ]; then
    ARGS="$ARGS -file $FILE"
fi
if [ "$JOURNALCTL_FILTER" != "" ]; then
    ARGS="$ARGS -jfilter $JOURNALCTL_FILTER"
fi
if [ "$TYPE" != "" ]; then
    ARGS="$ARGS -type $TYPE"
fi
if [ "$TEST_MODE" == "true" ] || [ "$TEST_MODE" == "TRUE" ]; then
    ARGS="$ARGS -t"
fi
if [ "$DISABLE_AGENT" == "true" ] || [ "$DISABLE_AGENT" == "TRUE" ]; then
    ARGS="$ARGS -no-cs"
fi
if [ "$DISABLE_API" == "true" ] || [ "$DISABLE_API" == "TRUE" ]; then
    ARGS="$ARGS -no-api"
fi
if [ "$LEVEL_TRACE" == "true" ] || [ "$LEVEL_TRACE" == "TRUE" ]; then
    ARGS="$ARGS -trace"
fi
if [ "$LEVEL_DEBUG" == "true" ] || [ "$LEVEL_DEBUG" == "TRUE"  ]; then
    ARGS="$ARGS -debug"
fi
if [ "$LEVEL_INFO" == "true" ] || [ "$LEVEL_INFO" == "TRUE" ]; then
    ARGS="$ARGS -info"
fi

exec crowdsec $ARGS