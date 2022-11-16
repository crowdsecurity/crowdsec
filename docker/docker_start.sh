#!/bin/bash

# shellcheck disable=SC2292      # allow [ test ] syntax
# shellcheck disable=SC2310      # allow "if function..." syntax with -e

set -e
shopt -s inherit_errexit

#- HELPER FUNCTIONS ----------------#

istrue() {
  case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
    true) return 0 ;;
    *) return 1 ;;
  esac
}

isfalse() {
    if istrue "$1"; then
        return 1
    else
        return 0
    fi
}

# generate a yaml list from a comma-separated string of values
csv2yaml() {
    [ -z "$1" ] && return
    echo "$1" | sed 's/,/\n- /g;s/^/- /g'
}

# wrap cscli with the correct config file location
cscli() {
    command cscli -c "$CONFIG_FILE" "$@"
}

conf_get() {
    if [ $# -ge 2 ]; then
        yq e "$1" "$2"
    else
        yq e "$1" "$CONFIG_FILE"
    fi
}

conf_set() {
    if [ $# -ge 2 ]; then
        yq e "$1" -i "$2"
    else
        yq e "$1" -i "$CONFIG_FILE"
    fi
}

#-----------------------------------#

# Check and prestage databases
for geodb in GeoLite2-ASN.mmdb GeoLite2-City.mmdb; do
    # We keep the pre-populated geoip databases in /staging instead of /var,
    # because if the data directory is bind-mounted from the host, it will be
    # empty and the files will be out of reach, requiring a runtime download.
    # We link to them to save about 80Mb compared to cp/mv.
    if [ ! -e "/var/lib/crowdsec/data/$geodb" ] && [ -e "/staging/var/lib/crowdsec/data/$geodb" ]; then
        mkdir -p /var/lib/crowdsec/data
        ln -s "/staging/var/lib/crowdsec/data/$geodb" /var/lib/crowdsec/data/
    fi
done

# Check and prestage /etc/crowdsec
if [ ! -e "/etc/crowdsec/local_api_credentials.yaml" ] && [ ! -e "/etc/crowdsec/config.yaml" ]; then
    cp -r /staging/etc/* /etc/
fi

# regenerate local agent credentials (ignore if agent is disabled)
if isfalse "$DISABLE_AGENT"; then
    echo "Regenerate local agent credentials"

    cscli machines delete "$CUSTOM_HOSTNAME"
    # shellcheck disable=SC2086
    cscli machines add "$CUSTOM_HOSTNAME" --auto --url "$LOCAL_API_URL"

    echo "set up lapi credentials for agent"
    lapi_credentials_path=$(conf_get '.api.client.credentials_path')

    if istrue "$USE_TLS"; then
        install -m 0600 /dev/null "$lapi_credentials_path"
        conf_set '
            .url = strenv(LOCAL_API_URL) |
            .ca_cert_path = strenv(CA_CERT_PATH) |
            .key_path = strenv(KEY_FILE) |
            .cert_path = strenv(CERT_FILE)
        ' "$lapi_credentials_path"
    elif [ "$AGENT_USERNAME" != "" ]; then
        install -m 0600 /dev/null "$lapi_credentials_path"
        conf_set '
            .url = strenv(LOCAL_API_URL) |
            .login = strenv(AGENT_USERNAME) |
            .password = strenv(AGENT_PASSWORD)
        ' "$lapi_credentials_path"
    fi
fi

echo "Check if lapi needs to automatically register an agent"

if isfalse "$DISABLE_LOCAL_API"; then
    if [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] ; then
        # shellcheck disable=SC2086
        cscli machines add "$AGENT_USERNAME" --password "$AGENT_PASSWORD" --url "$LOCAL_API_URL"
    fi

    if istrue "$USE_TLS"; then
        # shellcheck disable=SC2086
        cscli machines add "$AGENT_USERNAME" --url "$LOCAL_API_URL"
    fi

    echo "Agent registered to lapi"
fi

# registration to online API for signal push
if isfalse "$DISABLE_ONLINE_API" && [ "$CONFIG_FILE" == "/etc/crowdsec/config.yaml" ] ; then
    config_exists=$(conf_get '.api.server.online_client | has("credentials_path")')
    if isfalse "$config_exists"; then
        conf_set '.api.server.online_client = {"credentials_path": "/etc/crowdsec/online_api_credentials.yaml"}'
        cscli capi register > /etc/crowdsec/online_api_credentials.yaml
        echo "registration to online API done"
    fi
fi

# Enroll instance if enroll key is provided
if isfalse "$DISABLE_ONLINE_API" && [ "$ENROLL_KEY" != "" ]; then
    enroll_args=""
    if [ "$ENROLL_INSTANCE_NAME" != "" ]; then
        enroll_args="--name $ENROLL_INSTANCE_NAME"
    fi
    if [ "$ENROLL_TAGS" != "" ]; then
        # shellcheck disable=SC2086
        for tag in ${ENROLL_TAGS}; do
            enroll_args="$enroll_args --tags $tag"
        done
    fi
    # shellcheck disable=SC2086
    cscli console enroll $enroll_args "$ENROLL_KEY"
fi

# crowdsec sqlite database permissions
if [ "$GID" != "" ]; then
    if istrue "$(conf_get '.db_config.type == "sqlite"')"; then
        chown ":$GID" "$(conf_get '.db_config.db_path')"
        echo "sqlite database permissions updated"
    fi
fi

if istrue "$USE_TLS"; then
    agents_allowed_yaml=$(csv2yaml "$AGENTS_ALLOWED_OU") \
    bouncers_allowed_yaml=$(csv2yaml "$BOUNCERS_ALLOWED_OU") \
    conf_set '
        .api.server.tls.ca_cert_path = strenv(CA_CERT_PATH) |
        .api.server.tls.cert_file = strenv(CERT_FILE) |
        .api.server.tls.key_file = strenv(KEY_FILE) |
        .api.server.tls.bouncers_allowed_ou = env(bouncers_allowed_yaml) |
        .api.server.tls.agents_allowed_ou = env(agents_allowed_yaml) |
        ... comments=""
        '
fi

conf_set ".config_paths.plugin_dir = strenv(PLUGIN_DIR)"

## Install collections, parsers, scenarios & postoverflows
cscli hub update
cscli collections upgrade crowdsecurity/linux || true
cscli parsers upgrade crowdsecurity/whitelists || true
cscli parsers install crowdsecurity/docker-logs || true

if [ "$COLLECTIONS" != "" ]; then
    # shellcheck disable=SC2086
    cscli collections install $COLLECTIONS
fi

if [ "$PARSERS" != "" ]; then
    # shellcheck disable=SC2086
    cscli parsers install $PARSERS
fi

if [ "$SCENARIOS" != "" ]; then
    # shellcheck disable=SC2086
    cscli scenarios install $SCENARIOS
fi

if [ "$POSTOVERFLOWS" != "" ]; then
    # shellcheck disable=SC2086
    cscli postoverflows install $POSTOVERFLOWS
fi

## Remove collections, parsers, scenarios & postoverflows
if [ "$DISABLE_COLLECTIONS" != "" ]; then
    # shellcheck disable=SC2086
    cscli collections remove $DISABLE_COLLECTIONS
fi

if [ "$DISABLE_PARSERS" != "" ]; then
    # shellcheck disable=SC2086
    cscli parsers remove $DISABLE_PARSERS
fi

if [ "$DISABLE_SCENARIOS" != "" ]; then
    # shellcheck disable=SC2086
    cscli scenarios remove $DISABLE_SCENARIOS
fi

if [ "$DISABLE_POSTOVERFLOWS" != "" ]; then
    # shellcheck disable=SC2086
    cscli postoverflows remove $DISABLE_POSTOVERFLOWS
fi

register_bouncer() {
  if ! cscli bouncers list -o json | sed '/^ *"name"/!d;s/^ *"name": "\(.*\)",/\1/' | grep -q "^${NAME}$"; then
      if cscli bouncers add "${NAME}" -k "${KEY}" > /dev/null; then
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

if istrue "$TEST_MODE"; then
    ARGS="$ARGS -t"
fi

if istrue "$DISABLE_AGENT"; then
    ARGS="$ARGS -no-cs"
fi

if istrue "$DISABLE_LOCAL_API"; then
    ARGS="$ARGS -no-api"
fi

if istrue "$LEVEL_TRACE"; then
    ARGS="$ARGS -trace"
fi

if istrue "$LEVEL_DEBUG"; then
    ARGS="$ARGS -debug"
fi

if istrue "$LEVEL_INFO"; then
    ARGS="$ARGS -info"
fi

# shellcheck disable=SC2086
exec crowdsec $ARGS
