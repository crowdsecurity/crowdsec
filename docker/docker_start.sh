#!/bin/bash

# shellcheck disable=SC2292      # allow [ test ] syntax
# shellcheck disable=SC2310      # allow "if function..." syntax with -e

set -e
shopt -s inherit_errexit

# match true, TRUE, True, tRuE, etc.
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

if istrue "$DEBUG"; then
    set -x
    export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
fi

if istrue "$CI_TESTING"; then
    echo "githubciXXXXXXXXXXXXXXXXXXXXXXXX" >/etc/machine-id
fi

#- DEFAULTS -----------------------#

export CONFIG_FILE="${CONFIG_FILE:=/etc/crowdsec/config.yaml}"
export CUSTOM_HOSTNAME="${CUSTOM_HOSTNAME:=localhost}"

#- HELPER FUNCTIONS ----------------#

# csv2yaml <string>
# generate a yaml list from a comma-separated string of values
csv2yaml() {
    [ -z "$1" ] && return
    echo "$1" | sed 's/,/\n- /g;s/^/- /g'
}

# wrap cscli with the correct config file location
cscli() {
    command cscli -c "$CONFIG_FILE" "$@"
}

# conf_get <key> [file_path]
# retrieve a value from a file (by default $CONFIG_FILE)
conf_get() {
    if [ $# -ge 2 ]; then
        yq e "$1" "$2"
    else
        cscli config show-yaml | yq e "$1"
    fi
}

# conf_set <yq_expression> [file_path]
# evaluate a yq command (by default on $CONFIG_FILE),
# create the file if it doesn't exist
conf_set() {
    if [ $# -ge 2 ]; then
        YAML_FILE="$2"
    else
        YAML_FILE="$CONFIG_FILE"
    fi
    if [ ! -f "$YAML_FILE" ]; then
        install -m 0600 /dev/null "$YAML_FILE"
    fi
    yq e "$1" -i "$YAML_FILE"
}

# conf_set_if(): used to update the configuration
# only if a given variable is provided
# conf_set_if "$VAR" <yq_expression> [file_path]
conf_set_if() {
    if [ "$1" != "" ]; then
        shift
        conf_set "$@"
    fi
}

# register_bouncer <bouncer_name> <bouncer_key>
register_bouncer() {
  if ! cscli bouncers list -o json | sed '/^ *"name"/!d;s/^ *"name": "\(.*\)",/\1/' | grep -q "^${1}$"; then
      if cscli bouncers add "$1" -k "$2" > /dev/null; then
          echo "Registered bouncer for $1"
      else
          echo "Failed to register bouncer for $1"
      fi
  fi
}

# Call cscli to manage objects ignoring taint errors
# $1 can be collections, parsers, etc.
# $2 can be install, remove, upgrade
# $3 is a list of object names separated by space
cscli_if_clean() {
    local itemtype="$1"
    local action="$2"
    local objs=$3
    shift 3
    # loop over all objects
    for obj in $objs; do
        if cscli "$itemtype" inspect "$obj" -o json | yq -e '.tainted // false' >/dev/null 2>&1; then
            echo "Object $itemtype/$obj is tainted, skipping"
        else
#            # Too verbose? Only show errors if not in debug mode
#            if [ "$DEBUG" != "true" ]; then
#                error_only=--error
#            fi
            error_only=""
            echo "Running: cscli $error_only $itemtype $action \"$obj\" $*"
            # shellcheck disable=SC2086
            cscli $error_only "$itemtype" "$action" "$obj" "$@"
        fi
    done
}

# Output the difference between two lists
# of items separated by spaces
difference() {
  list1="$1"
  list2="$2"

  # split into words
  # shellcheck disable=SC2086
  set -- $list1
  for item in "$@"; do
    found=false
    for i in $list2; do
      if [ "$item" = "$i" ]; then
        found=true
        break
      fi
    done
    if [ "$found" = false ]; then
      echo "$item"
    fi
  done
}

#-----------------------------------#

if [ -n "$CERT_FILE" ] || [ -n "$KEY_FILE" ] ; then
    printf '%b' '\033[0;33m'
    echo "Warning: the variables CERT_FILE and KEY_FILE have been deprecated." >&2
    echo "Please use LAPI_CERT_FILE and LAPI_KEY_FILE insted." >&2
    echo "The old variables will be removed in a future release." >&2
    printf '%b' '\033[0m'
    export LAPI_CERT_FILE=${LAPI_CERT_FILE:-$CERT_FILE}
    export LAPI_KEY_FILE=${LAPI_KEY_FILE:-$KEY_FILE}
fi

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
        rsync -av --ignore-existing /staging/etc/crowdsec/* /etc/crowdsec
    fi
fi

# do this as soon as we have a config.yaml, to avoid useless warnings
if istrue "$USE_WAL"; then
    conf_set '.db_config.use_wal = true'
elif [ -n "$USE_WAL" ] && isfalse "$USE_WAL"; then
    conf_set '.db_config.use_wal = false'
fi

lapi_credentials_path=$(conf_get '.api.client.credentials_path')

if isfalse "$DISABLE_LOCAL_API"; then
    # generate local agent credentials (even if agent is disabled, cscli needs a
    # connection to the API)
    if ( isfalse "$USE_TLS" || [ "$CLIENT_CERT_FILE" = "" ] ); then
        if yq -e '.login==strenv(CUSTOM_HOSTNAME)' "$lapi_credentials_path" >/dev/null && ( cscli machines list -o json | yq -e 'any_c(.machineId==strenv(CUSTOM_HOSTNAME))' >/dev/null ); then
            echo "Local agent already registered"
        else
            echo "Generate local agent credentials"
            # if the db is persistent but the credentials are not, we need to
            # delete the old machine to generate new credentials
            cscli machines delete "$CUSTOM_HOSTNAME" >/dev/null 2>&1 || true
            cscli machines add "$CUSTOM_HOSTNAME" --auto --force
        fi
    fi

    echo "Check if lapi needs to register an additional agent"
    # pre-registration is not needed with TLS authentication, but we can have TLS transport with user/pw
    if [ "$AGENT_USERNAME" != "" ] && [ "$AGENT_PASSWORD" != "" ] ; then
        # re-register because pw may have been changed
        cscli machines add "$AGENT_USERNAME" --password "$AGENT_PASSWORD" -f /dev/null --force
        echo "Agent registered to lapi"
    fi
fi

# ----------------

conf_set_if "$LOCAL_API_URL" '.url = strenv(LOCAL_API_URL)' "$lapi_credentials_path"

if istrue "$DISABLE_LOCAL_API"; then
    # we only use the envvars that are actually defined
    # in case of persistent configuration
    conf_set_if "$AGENT_USERNAME" '.login = strenv(AGENT_USERNAME)' "$lapi_credentials_path"
    conf_set_if "$AGENT_PASSWORD" '.password = strenv(AGENT_PASSWORD)' "$lapi_credentials_path"
fi

conf_set_if "$INSECURE_SKIP_VERIFY" '.api.client.insecure_skip_verify = env(INSECURE_SKIP_VERIFY)'

# agent-only containers still require USE_TLS
if istrue "$USE_TLS"; then
    # shellcheck disable=SC2153
    conf_set_if "$CACERT_FILE" '.ca_cert_path = strenv(CACERT_FILE)' "$lapi_credentials_path"
    conf_set_if "$CLIENT_KEY_FILE" '.key_path = strenv(CLIENT_KEY_FILE)' "$lapi_credentials_path"
    conf_set_if "$CLIENT_CERT_FILE" '.cert_path = strenv(CLIENT_CERT_FILE)' "$lapi_credentials_path"
else
    conf_set '
        del(.ca_cert_path) |
        del(.key_path) |
        del(.cert_path)
    ' "$lapi_credentials_path"
fi

if istrue "$DISABLE_ONLINE_API"; then
    conf_set 'del(.api.server.online_client)'
fi

# registration to online API for signal push
if isfalse "$DISABLE_LOCAL_API" && isfalse "$DISABLE_ONLINE_API" ; then
    CONFIG_DIR=$(conf_get '.config_paths.config_dir')
    export CONFIG_DIR
    config_exists=$(conf_get '.api.server.online_client | has("credentials_path")')
    if isfalse "$config_exists"; then
        conf_set '.api.server.online_client = {"credentials_path": strenv(CONFIG_DIR) + "/online_api_credentials.yaml"}'
        cscli capi register > "$CONFIG_DIR/online_api_credentials.yaml"
        echo "Registration to online API done"
    fi
fi

# Enroll instance if enroll key is provided
if isfalse "$DISABLE_LOCAL_API" && isfalse "$DISABLE_ONLINE_API" && [ "$ENROLL_KEY" != "" ]; then
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
        # don't fail if the db is not there yet
        chown -f ":$GID" "$(conf_get '.db_config.db_path')" 2>/dev/null \
            && echo "sqlite database permissions updated" \
            || true
    fi
fi

if isfalse "$DISABLE_LOCAL_API" && istrue "$USE_TLS"; then
    agents_allowed_yaml=$(csv2yaml "$AGENTS_ALLOWED_OU")
    export agents_allowed_yaml
    bouncers_allowed_yaml=$(csv2yaml "$BOUNCERS_ALLOWED_OU")
    export bouncers_allowed_yaml
    conf_set_if "$CACERT_FILE" '.api.server.tls.ca_cert_path = strenv(CACERT_FILE)'
    conf_set_if "$LAPI_CERT_FILE" '.api.server.tls.cert_file = strenv(LAPI_CERT_FILE)'
    conf_set_if "$LAPI_KEY_FILE" '.api.server.tls.key_file = strenv(LAPI_KEY_FILE)'
    conf_set_if "$BOUNCERS_ALLOWED_OU" '.api.server.tls.bouncers_allowed_ou = env(bouncers_allowed_yaml)'
    conf_set_if "$AGENTS_ALLOWED_OU" '.api.server.tls.agents_allowed_ou = env(agents_allowed_yaml)'
else
    conf_set 'del(.api.server.tls)'
fi

conf_set_if "$PLUGIN_DIR" '.config_paths.plugin_dir = strenv(PLUGIN_DIR)'

## Install hub items
cscli hub update

cscli_if_clean collections upgrade crowdsecurity/linux
cscli_if_clean parsers upgrade crowdsecurity/whitelists
cscli_if_clean parsers install crowdsecurity/docker-logs
cscli_if_clean parsers install crowdsecurity/cri-logs

if [ "$COLLECTIONS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean collections install "$(difference "$COLLECTIONS" "$DISABLE_COLLECTIONS")"
fi

if [ "$PARSERS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean parsers install "$(difference "$PARSERS" "$DISABLE_PARSERS")"
fi

if [ "$SCENARIOS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean scenarios install "$(difference "$SCENARIOS" "$DISABLE_SCENARIOS")"
fi

if [ "$POSTOVERFLOWS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean postoverflows install "$(difference "$POSTOVERFLOWS" "$DISABLE_POSTOVERFLOWS")"
fi

if [ "$CONTEXTS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean contexts install "$(difference "$CONTEXTS" "$DISABLE_CONTEXTS")"
fi

if [ "$APPSEC_CONFIGS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean appsec-configs install "$(difference "$APPSEC_CONFIGS" "$DISABLE_APPSEC_CONFIGS")"
fi

if [ "$APPSEC_RULES" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean appsec-rules install "$(difference "$APPSEC_RULES" "$DISABLE_APPSEC_RULES")"
fi

## Remove collections, parsers, scenarios & postoverflows
if [ "$DISABLE_COLLECTIONS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean collections remove "$DISABLE_COLLECTIONS" --force
fi

if [ "$DISABLE_PARSERS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean parsers remove "$DISABLE_PARSERS" --force
fi

if [ "$DISABLE_SCENARIOS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean scenarios remove "$DISABLE_SCENARIOS" --force
fi

if [ "$DISABLE_POSTOVERFLOWS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean postoverflows remove "$DISABLE_POSTOVERFLOWS" --force
fi

if [ "$DISABLE_CONTEXTS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean contexts remove "$DISABLE_CONTEXTS" --force
fi

if [ "$DISABLE_APPSEC_CONFIGS" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean appsec-configs remove "$DISABLE_APPSEC_CONFIGS" --force
fi

if [ "$DISABLE_APPSEC_RULES" != "" ]; then
    # shellcheck disable=SC2086
    cscli_if_clean appsec-rules remove "$DISABLE_APPSEC_RULES" --force
fi

## Register bouncers via env
for BOUNCER in $(compgen -A variable | grep -i BOUNCER_KEY); do
    KEY=$(printf '%s' "${!BOUNCER}")
    NAME=$(printf '%s' "$BOUNCER" | cut -d_  -f3-)
    if [[ -n $KEY ]] && [[ -n $NAME ]]; then
        register_bouncer "$NAME" "$KEY"
    fi
done

if [ "$ENABLE_CONSOLE_MANAGEMENT" != "" ]; then
    # shellcheck disable=SC2086
    cscli console enable console_management
fi

## Register bouncers via secrets (Swarm only)
shopt -s nullglob extglob
for BOUNCER in /run/secrets/@(bouncer_key|BOUNCER_KEY)* ; do
    KEY=$(cat "${BOUNCER}")
    NAME=$(echo "${BOUNCER}" | awk -F "/" '{printf $NF}' | cut -d_  -f2-)
    if [[ -n $KEY ]] && [[ -n $NAME ]]; then
        register_bouncer "$NAME" "$KEY"
    fi
done
shopt -u nullglob extglob

# set all options before validating the configuration

conf_set_if "$CAPI_WHITELISTS_PATH" '.api.server.capi_whitelists_path = strenv(CAPI_WHITELISTS_PATH)'
conf_set_if "$METRICS_PORT" '.prometheus.listen_port=env(METRICS_PORT)'

if istrue "$DISABLE_LOCAL_API"; then
    conf_set '.api.server.enable=false'
else
    conf_set '.api.server.enable=true'
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

if istrue "$TEST_MODE"; then
    ARGS="$ARGS -t"
fi

if istrue "$DISABLE_AGENT"; then
    ARGS="$ARGS -no-cs"
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
