#!/bin/sh

# Set the crowdsec config file
CS_CONFIG_FILE="/etc/crowdsec/config.yaml"
if [ "$CONFIG_FILE" != "" ]; then
    CS_CONFIG_FILE="$CONFIG_FILE"
fi

# regenerate lcaol agent credentials (ignore if agent is disabled)
if [ "$DISABLE_AGENT" == "" ] ; then
    echo "Regenerate local agent credentials"
    cscli -c "$CS_CONFIG_FILE" machines delete localhost
    cscli -c "$CS_CONFIG_FILE" machines add localhost --auto
    if [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] && [ "$LOCAL_API_URL" != "" ] ; then
        echo "set up lapi credentials for agent"
        CONFIG_PATH=$(yq eval '.api.client.credentials_path' "$CS_CONFIG_FILE" )
        echo "url: $LOCAL_API_URL" > $CONFIG_PATH
        echo "login: $AGENT_USERNAME" >> $CONFIG_PATH
        echo "password: $AGENT_PASSWORD" >> $CONFIG_PATH
    fi
fi

# Check if lapi need to register automatically an agent
echo Check if lapi need to register automatically an agent
if [ "$DISABLE_LOCAL_API" == "" ] && [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] ; then
    cscli -c "$CS_CONFIG_FILE" machines add $AGENT_USERNAME --password $AGENT_PASSWORD
    echo "Agent registered to lapi"
fi

# registration to online API for signal push
if [ "$DISABLE_ONLINE_API" == "" ] && [ "$CONFIG_FILE" == "" ] ; then
    CONFIG_EXIST=$(yq eval '.api.server.online_client | has("credentials_path")' "$CS_CONFIG_FILE")
    if [ "$CONFIG_EXIST" != "true" ]; then
        yq eval '.api.server.online_client = {"credentials_path": "/etc/crowdsec/online_api_credentials.yaml"}' "$CS_CONFIG_FILE" > /etc/crowdsec/config2.yaml
        mv /etc/crowdsec/config2.yaml "$CS_CONFIG_FILE"
        cscli -c "$CS_CONFIG_FILE" capi register > /etc/crowdsec/online_api_credentials.yaml
        echo "registration to online API done"
    fi
fi

# crowdsec sqlite database permissions
if [ "$GID" != "" ]; then
    IS_SQLITE=$(yq eval '.db_config.type == "sqlite"' "$CS_CONFIG_FILE")
    DB_PATH=$(yq eval '.db_config.db_path' "$CS_CONFIG_FILE")
    if [ "$IS_SQLITE" == "true" ]; then
        chown :$GID $DB_PATH
        echo "sqlite database permissions updated"
    fi
fi

## Install collections, parsers & scenarios
cscli -c "$CS_CONFIG_FILE" hub update
cscli -c "$CS_CONFIG_FILE" collections upgrade crowdsecurity/linux || true
cscli -c "$CS_CONFIG_FILE" parsers upgrade crowdsecurity/whitelists || true
cscli -c "$CS_CONFIG_FILE" parsers install crowdsecurity/docker-logs || true
if [ "$COLLECTIONS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" collections install $COLLECTIONS
fi
if [ "$PARSERS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" parsers install $PARSERS
fi
if [ "$SCENARIOS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" scenarios install $SCENARIOS
fi
if [ "$POSTOVERFLOWS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" postoverflows install $POSTOVERFLOWS
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