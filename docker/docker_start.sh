#!/bin/bash

# Set the crowdsec config file
CS_CONFIG_FILE="/etc/crowdsec/config.yaml"
if [ "$CONFIG_FILE" != "" ]; then
    CS_CONFIG_FILE="$CONFIG_FILE"
fi

# TLS defaults
CERT_FILE="${CERT_FILE:-/etc/ssl/cert.pem}"
KEY_FILE="${KEY_FILE:-/etc/ssl/key.pem}"

# Plugins directory default
PLUGIN_DIR="${PLUGIN_DIR:-/usr/local/lib/crowdsec/plugins/}"

#Check & prestage databases
if [ ! -e "/var/lib/crowdsec/data/GeoLite2-ASN.mmdb" ] && [ ! -e "/var/lib/crowdsec/data/GeoLite2-City.mmdb" ]; then
    mkdir -p /var/lib/crowdsec/data
    cp /staging/var/lib/crowdsec/data/*.mmdb /var/lib/crowdsec/data/
fi

#Check & prestage /etc/crowdsec
if [ ! -e "/etc/crowdsec/local_api_credentials.yaml" ] && [ ! -e "/etc/crowdsec/config.yaml" ]; then
    mkdir -p /etc/crowdsec
    cp -r /staging/etc/* /etc/
fi

# regenerate local agent credentials (ignore if agent is disabled)
if [ "$DISABLE_AGENT" == "" ] ; then
    echo "Regenerate local agent credentials"
    cscli -c "$CS_CONFIG_FILE" machines delete ${CUSTOM_HOSTNAME:-localhost}
    if [ "$LOCAL_API_URL" != "" ] ; then
        cscli -c "$CS_CONFIG_FILE" machines add ${CUSTOM_HOSTNAME:-localhost} --auto --url $LOCAL_API_URL
    else
        cscli -c "$CS_CONFIG_FILE" machines add ${CUSTOM_HOSTNAME:-localhost} --auto
    fi
    if [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] && [ "$LOCAL_API_URL" != "" ] ; then
        echo "set up lapi credentials for agent"
        CONFIG_PATH=$(yq eval '.api.client.credentials_path' "$CS_CONFIG_FILE" )
        echo "url: $LOCAL_API_URL" > $CONFIG_PATH
        echo "login: $AGENT_USERNAME" >> $CONFIG_PATH
        echo "password: $AGENT_PASSWORD" >> $CONFIG_PATH
    fi
fi

# Check if lapi needs to automatically register an agent
echo "Check if lapi need to register automatically an agent"
if [ "$DISABLE_LOCAL_API" == "" ] && [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] ; then
    if [ "$LOCAL_API_URL" != "" ] ; then
        cscli -c "$CS_CONFIG_FILE" machines add $AGENT_USERNAME --password $AGENT_PASSWORD --url $LOCAL_API_URL
    else
        cscli -c "$CS_CONFIG_FILE" machines add $AGENT_USERNAME --password $AGENT_PASSWORD
    fi
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

if [ "$USE_TLS" != "" ]; then
   yq -i eval ".api.server.tls.cert_file = \"$CERT_FILE\"" "$CS_CONFIG_FILE"
   yq -i eval ".api.server.tls.key_file = \"$KEY_FILE\"" "$CS_CONFIG_FILE"
   yq -i eval '... comments=""' "$CS_CONFIG_FILE"
fi

if [ "$PLUGIN_DIR" != "/usr/local/lib/crowdsec/plugins/" ]; then
   yq -i eval ".config_paths.plugin_dir = \"$PLUGIN_DIR\"" "$CS_CONFIG_FILE"
fi

## Install collections, parsers, scenarios & postoverflows
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

## Remove collections, parsers, scenarios & postoverflows
if [ "$DISABLE_COLLECTIONS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" collections remove $DISABLE_COLLECTIONS
fi
if [ "$DISABLE_PARSERS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" parsers remove $DISABLE_PARSERS
fi
if [ "$DISABLE_SCENARIOS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" scenarios remove $DISABLE_SCENARIOS
fi
if [ "$DISABLE_POSTOVERFLOWS" != "" ]; then
    cscli -c "$CS_CONFIG_FILE" postoverflows remove $DISABLE_POSTOVERFLOWS
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
