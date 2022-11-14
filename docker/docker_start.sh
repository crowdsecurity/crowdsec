#!/bin/bash

echo "CONFIG_FILE: $CONFIG_FILE"
echo "DISABLE_ONLINE_API: $DISABLE_ONLINE_API"
echo "USE_TLS: $USE_TLS"
echo "CA_CERT_PATH: $CA_CERT_PATH"
echo "CERT_FILE: $CERT_FILE"
echo "KEY_FILE: $KEY_FILE"

# Plugins directory default
PLUGIN_DIR="${PLUGIN_DIR:-/usr/local/lib/crowdsec/plugins/}"

# Check & prestage databases
for geodb in GeoLite2-ASN.mmdb GeoLite2-City.mmdb; do
    # We keep the pre-populated geoib databases in /staging instead of /var,
    # because if the data directory is bind-mounted from the host, it will be
    # empty and the files will be out of reach, requiring a runtime download.
    # We link to them to save about 80Mb compared to cp/mv.
    if [ ! -e "/var/lib/crowdsec/data/$geodb" ] && [ -e "/staging/var/lib/crowdsec/data/$geodb" ]; then
        mkdir -p /var/lib/crowdsec/data
        ln -s "/staging/var/lib/crowdsec/data/$geodb" /var/lib/crowdsec/data/
    fi
done

#Check & prestage /etc/crowdsec
if [ ! -e "/etc/crowdsec/local_api_credentials.yaml" ] && [ ! -e "/etc/crowdsec/config.yaml" ]; then
    mkdir -p /etc/crowdsec
    cp -r /staging/etc/* /etc/
fi

# regenerate local agent credentials (ignore if agent is disabled)
if [ "$DISABLE_AGENT" == "" ] ; then
    echo "Regenerate local agent credentials"
    cscli -c "$CONFIG_FILE" machines delete "${CUSTOM_HOSTNAME:-localhost}"
    if [ "$LOCAL_API_URL" != "" ] ; then
        cscli -c "$CONFIG_FILE" machines add "${CUSTOM_HOSTNAME:-localhost}" --auto --url "$LOCAL_API_URL"
    else
        cscli -c "$CONFIG_FILE" machines add "${CUSTOM_HOSTNAME:-localhost}" --auto
    fi
    if [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] && [ "$LOCAL_API_URL" != "" ] ; then
        echo "set up lapi credentials for agent"
        CONFIG_PATH=$(yq eval '.api.client.credentials_path' "$CONFIG_FILE" )
        echo "url: $LOCAL_API_URL" > "$CONFIG_PATH"
        echo "login: $AGENT_USERNAME" >> "$CONFIG_PATH"
        echo "password: $AGENT_PASSWORD" >> "$CONFIG_PATH"
    fi
fi

# Check if lapi needs to automatically register an agent
echo "Check if lapi need to register automatically an agent"
if [ "$DISABLE_LOCAL_API" == "" ] && [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] ; then
    if [ "$LOCAL_API_URL" != "" ] ; then
        cscli -c "$CONFIG_FILE" machines add "$AGENT_USERNAME" --password "$AGENT_PASSWORD" --url "$LOCAL_API_URL"
    else
        cscli -c "$CONFIG_FILE" machines add "$AGENT_USERNAME" --password "$AGENT_PASSWORD"
    fi
    echo "Agent registered to lapi"
fi

# registration to online API for signal push
if [ "${DISABLE_ONLINE_API,,}" != "true" ] && [ "$CONFIG_FILE" == "/etc/crowdsec/config.yaml" ] ; then
    CONFIG_EXIST=$(yq eval '.api.server.online_client | has("credentials_path")' "$CONFIG_FILE")
    if [ "$CONFIG_EXIST" != "true" ]; then
        yq eval '.api.server.online_client = {"credentials_path": "/etc/crowdsec/online_api_credentials.yaml"}' "$CONFIG_FILE" > /etc/crowdsec/config2.yaml
        mv /etc/crowdsec/config2.yaml "$CONFIG_FILE"
        cscli -c "$CONFIG_FILE" capi register > /etc/crowdsec/online_api_credentials.yaml
        echo "registration to online API done"
    fi
fi

## Enroll instance if enroll key is provided
if [ "${DISABLE_ONLINE_API,,}" != "true" ] && [ "$ENROLL_KEY" != "" ] ; then
    enroll_args=""
    if [ "$ENROLL_INSTANCE_NAME"  != "" ] ; then
        enroll_args="--name $ENROLL_INSTANCE_NAME"
    fi
    if [ "$ENROLL_TAGS"  != "" ] ; then
        #shellcheck disable=SC2086
        for tag in ${ENROLL_TAGS}
        do
            enroll_args="$enroll_args --tags $tag"
        done
    fi
    #shellcheck disable=SC2086
    cscli console enroll $enroll_args "$ENROLL_KEY"
fi

# crowdsec sqlite database permissions
if [ "$GID" != "" ]; then
    IS_SQLITE=$(yq eval '.db_config.type == "sqlite"' "$CONFIG_FILE")
    DB_PATH=$(yq eval '.db_config.db_path' "$CONFIG_FILE")
    if [ "$IS_SQLITE" == "true" ]; then
        chown ":$GID" "$DB_PATH"
        echo "sqlite database permissions updated"
    fi
fi

if [ "${USE_TLS,,}" == "true" ]; then
    yq -i eval '
        .api.server.tls.ca_cert_path = strenv(CA_CERT_PATH) |
        .api.server.tls.cert_file = strenv(CERT_FILE) |
        .api.server.tls.key_file = strenv(KEY_FILE) |
        ... comments=""
        ' "$CONFIG_FILE"
fi

if [ "$PLUGIN_DIR" != "/usr/local/lib/crowdsec/plugins/" ]; then
    yq -i eval ".config_paths.plugin_dir = \"$PLUGIN_DIR\"" "$CONFIG_FILE"
fi

## Install collections, parsers, scenarios & postoverflows
cscli -c "$CONFIG_FILE" hub update
cscli -c "$CONFIG_FILE" collections upgrade crowdsecurity/linux || true
cscli -c "$CONFIG_FILE" parsers upgrade crowdsecurity/whitelists || true
cscli -c "$CONFIG_FILE" parsers install crowdsecurity/docker-logs || true

if [ "$COLLECTIONS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" collections install $COLLECTIONS
fi

if [ "$PARSERS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" parsers install $PARSERS
fi

if [ "$SCENARIOS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" scenarios install $SCENARIOS
fi

if [ "$POSTOVERFLOWS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" postoverflows install $POSTOVERFLOWS
fi

## Remove collections, parsers, scenarios & postoverflows
if [ "$DISABLE_COLLECTIONS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" collections remove $DISABLE_COLLECTIONS
fi

if [ "$DISABLE_PARSERS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" parsers remove $DISABLE_PARSERS
fi

if [ "$DISABLE_SCENARIOS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" scenarios remove $DISABLE_SCENARIOS
fi

if [ "$DISABLE_POSTOVERFLOWS" != "" ]; then
    #shellcheck disable=SC2086
    cscli -c "$CONFIG_FILE" postoverflows remove $DISABLE_POSTOVERFLOWS
fi

function register_bouncer {
  if ! cscli -c "$CONFIG_FILE" bouncers list -o json | sed '/^ *"name"/!d;s/^ *"name": "\(.*\)",/\1/' | grep -q "^${NAME}$"; then
      if cscli -c "$CONFIG_FILE" bouncers add "${NAME}" -k "${KEY}" > /dev/null; then
          echo "Registered bouncer for ${NAME}"
      else
          echo "Failed to register bouncer for ${NAME}"
      fi
  fi
}

## Register bouncers via env
for BOUNCER in $(compgen -A variable | grep -i BOUNCER_KEY); do
    KEY=$(printf '%s' "${!BOUNCER}")
    NAME=$(printf '%s' "$BOUNCER" | cut -d_  -f2-)
    if [[ -n $KEY ]] && [[ -n $NAME ]]; then
        register_bouncer
    fi
done

## Register bouncers via secrets
shopt -s nullglob extglob
for BOUNCER in /run/secrets/@(bouncer_key|BOUNCER_KEY)* ; do
    KEY=$(cat "${BOUNCER}")
    NAME=$(echo "${BOUNCER}" | awk -F "/" '{printf $NF}' | cut -d_  -f2-)
    if [[ -n $KEY ]] && [[ -n $NAME ]]; then    
        register_bouncer
    fi
done
shopt -u nullglob extglob

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
if [ "${TEST_MODE,,}" == "true" ]; then
    ARGS="$ARGS -t"
fi
if [ "${DISABLE_AGENT,,}" == "true" ]; then
    ARGS="$ARGS -no-cs"
fi
if [ "${DISABLE_LOCAL_API,,}" == "true" ]; then
    ARGS="$ARGS -no-api"
fi
if [ "${LEVEL_TRACE,,}" == "true" ]; then
    ARGS="$ARGS -trace"
fi
if [ "${LEVEL_DEBUG,,}" == "true" ]; then
    ARGS="$ARGS -debug"
fi
if [ "${LEVEL_INFO,,}" == "true" ]; then
    ARGS="$ARGS -info"
fi

#shellcheck disable=SC2086
exec crowdsec $ARGS
