#!/bin/sh

# Check if the container has already been started (ignore if agent is disabled)
if [ "$DISABLE_AGENT" == "" ] ; then
    echo "Check if the container has already been started (ignore if agent is disabled)"
    cscli machines list | grep localhost
    if [ "$?" == 1 ]; then
        cscli machines add localhost --auto
    fi
    if [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] && [ "$LOCAL_API_URL" != "" ] ; then
        echo "set up lapi credentials for agent"
        CONFIG_PATH=$(yq eval '.api.client.credentials_path' /etc/crowdsec/config.yaml)
        echo "url: $LOCAL_API_URL" > $CONFIG_PATH
        echo "login: $AGENT_USERNAME" >> $CONFIG_PATH
        echo "password: $AGENT_PASSWORD" >> $CONFIG_PATH
    fi
fi

# Check if lapi need to register automatically an agent
echo Check if lapi need to register automatically an agent
if [ "$DISABLE_LOCAL_API" == "" ] && [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] ; then
    cscli machines add $AGENT_USERNAME --password $AGENT_PASSWORD
    echo "Agent registered to lapi"
fi

# registration to online API for signal push
if [ "$DISABLE_ONLINE_API" == "" ] && [ "$CONFIG_FILE" == "" ] ; then
    CONFIG_EXIST=$(yq eval '.api.server.online_client | has("credentials_path")' /etc/crowdsec/config.yaml)
    if [ "$CONFIG_EXIST" != "true" ]; then
        yq eval '.api.server.online_client = {"credentials_path": "/etc/crowdsec/online_api_credentials.yaml"}' /etc/crowdsec/config.yaml > /etc/crowdsec/config2.yaml
        mv /etc/crowdsec/config2.yaml /etc/crowdsec/config.yaml
        cscli capi register > /etc/crowdsec/online_api_credentials.yaml
        echo "registration to online API done"
    fi
fi

# crowdsec sqlite database permissions
if [ "$GID" != "" ]; then
    IS_SQLITE=$(yq eval '.db_config.type == "sqlite"' /etc/crowdsec/config.yaml)
    DB_PATH=$(yq eval '.db_config.db_path' /etc/crowdsec/config.yaml)
    if [ "$IS_SQLITE" == "true" ]; then
        chown :$GID $DB_PATH
        echo "sqlite database permissions updated"
    fi
fi

## Install collections, parsers & scenarios
cscli hub update
cscli collections upgrade crowdsecurity/linux || true
cscli parsers upgrade crowdsecurity/whitelists || true
cscli parsers install crowdsecurity/docker-logs || true
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
if [ "$DSN" != "" ]; then
    ARGS="$ARGS -dsn ${DSN}"
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
if [ "$DISABLE_LOCAL_API" == "true" ] || [ "$DISABLE_LOCAL_API" == "TRUE" ]; then
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