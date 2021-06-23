#!/bin/sh

# Check if the container has already been started
cscli machines list | grep 127.0.0.1
if [ $? == 1 ]; then
    cscli machines add --force --auto -f /etc/crowdsec/local_api_credentials.yaml
fi

# registration to online API for signal push
if [ "$DISABLE_ONLINE_API" == "" ] && [ "$CONFIG_FILE" == "" ] ; then
    CONFIG_EXIST=$(yq eval '.api.server.online_client | has("credentials_path")' /etc/crowdsec/config.yaml)
    if [ "$CONFIG_EXIST" != "true" ]; then
        yq eval '.api.server.online_client = {"credentials_path": "/etc/crowdsec/online_api_credentials.yaml"}' /etc/crowdsec/config.yaml > /etc/crowdsec/config2.yaml
        mv /etc/crowdsec/config2.yaml /etc/crowdsec/config.yaml
        cscli capi register > /etc/crowdsec/online_api_credentials.yaml
    fi
fi

# crowdsec sqlite database permissions
if [ "$GID" != "" ]; then
    IS_SQLITE=$(yq eval '.db_config.type == "sqlite"' /etc/crowdsec/config.yaml)
    DB_PATH=$(yq eval '.db_config.db_path' /etc/crowdsec/config.yaml)
    if [ "$IS_SQLITE" == "true" ]; then
        chown :$GID $DB_PATH
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
    ARGS="$ARGS -file $FILE_PATH"
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
