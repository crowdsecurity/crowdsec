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

# conf_set <yq_expression> [file_path]
# evaluate a yq command (by default on CONFIG_FILE),
# create the file if it doesn't exist
conf_set() {
    if [ $# -ge 2 ]; then
        YAML_FILE=$2
    else
        YAML_FILE=$CONFIG_FILE
    fi
    YAML_CONTENT=$(cat "$YAML_FILE" 2>/dev/null || true)
    echo "$YAML_CONTENT" | yq e "$1" | install -m 0600 /dev/stdin "$YAML_FILE"
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
    echo "Populating configuration directory..."
    # don't overwrite existing configuration files, which may come
    # from bind-mount or even be read-only (configmaps)
    if [ -e /staging/etc/crowdsec ]; then
        mkdir -p /etc/crowdsec/
        # if you change this, check that it still works
        # under alpine and k8s, with and without tls
        cp -an /staging/etc/crowdsec/* /etc/crowdsec/
    fi
fi

# do this as soon as we have a config.yaml, to avoid useless warnings
if istrue "$USE_WAL"; then
    conf_set '.db_config.use_wal = true'
elif [ -n "$USE_WAL" ] && isfalse "$USE_WAL"; then
    conf_set '.db_config.use_wal = false'
fi

# regenerate local agent credentials (ignore if agent is disabled)
if isfalse "$DISABLE_AGENT"; then
    if isfalse "$DISABLE_LOCAL_API"; then
        echo "Regenerate local agent credentials"
        cscli machines delete "$CUSTOM_HOSTNAME" 2>/dev/null || true
        # shellcheck disable=SC2086
        cscli machines add "$CUSTOM_HOSTNAME" --auto --url "$LOCAL_API_URL"
    fi

    lapi_credentials_path=$(conf_get '.api.client.credentials_path')

    # we only use the envvars that are actually defined
    # in case of persistent configuration
    conf_set '
        with(select(strenv(LOCAL_API_URL)!=""); .url = strenv(LOCAL_API_URL)) |
        with(select(strenv(AGENT_USERNAME)!=""); .login = strenv(AGENT_USERNAME)) |
        with(select(strenv(AGENT_PASSWORD)!=""); .password = strenv(AGENT_PASSWORD))
        ' "$lapi_credentials_path"
    fi
    if istrue "$USE_TLS"; then
        conf_set '
            with(select(strenv(CACERT_FILE)!=""); .ca_cert_path = strenv(CACERT_FILE)) |
            with(select(strenv(KEY_FILE)!=""); .key_path = strenv(KEY_FILE)) |
            with(select(strenv(CERT_FILE)!=""); .cert_path = strenv(CERT_FILE)) |
        ' "$lapi_credentials_path"
    fi

if isfalse "$DISABLE_LOCAL_API"; then
    echo "Check if lapi needs to automatically register an agent"

    # pre-registration is not needed with TLS
    if isfalse "$USE_TLS" && [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] ; then
        # shellcheck disable=SC2086
        cscli machines add "$AGENT_USERNAME" --password "$AGENT_PASSWORD" --url "$LOCAL_API_URL"
        echo "Agent registered to lapi"
    fi
fi

# registration to online API for signal push
if isfalse "$DISABLE_ONLINE_API" && [ "$CONFIG_FILE" == "/etc/crowdsec/config.yaml" ] ; then
    config_exists=$(conf_get '.api.server.online_client | has("credentials_path")')
    if isfalse "$config_exists"; then
        conf_set '.api.server.online_client = {"credentials_path": "/etc/crowdsec/online_api_credentials.yaml"}'
        cscli capi register > /etc/crowdsec/online_api_credentials.yaml
        echo "Registration to online API done"
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
        .api.server.tls.ca_cert_path = strenv(CACERT_FILE) |
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
    NAME=$(printf '%s' "$BOUNCER" | cut -d_  -f3-)
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

conf_set '.prometheus.listen_port=env(METRICS_PORT)'

# shellcheck disable=SC2086
exec crowdsec $ARGS
