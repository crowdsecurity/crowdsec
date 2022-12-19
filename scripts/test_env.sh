#!/bin/sh

set -e

# XXX this can't be a good place to make the tree
BASE="./tests"

usage() {
	  echo "Usage:"
	  echo "    $0 -h                             Display this help message."
	  echo "    $0 -d ./tests                     Create test environment in './tests' folder"
	  exit 0
}

set_colors() {
    FG_BLACK=""
    FG_RED=""
    FG_GREEN=""
    FG_YELLOW=""
    FG_BLUE=""
    FG_MAGENTA=""
    FG_CYAN=""
    FG_WHITE=""
    BOLD=""
    RESET=""

    #shellcheck disable=SC2034
    if tput sgr0 >/dev/null; then
        FG_BLACK=$(tput setaf 0)
        FG_RED=$(tput setaf 1)
        FG_GREEN=$(tput setaf 2)
        FG_YELLOW=$(tput setaf 3)
        FG_BLUE=$(tput setaf 4)
        FG_MAGENTA=$(tput setaf 5)
        FG_CYAN=$(tput setaf 6)
        FG_WHITE=$(tput setaf 7)
        BOLD=$(tput bold)
        RESET=$(tput sgr0)
    fi
}

log_info() {
	msg=$1
	date=$(date +%x:%X)
	echo "{FG_BLUE}INFO${RESET}[${date}] $msg"
}

log_err() {
    msg=$1
    date=$(date +%x:%X)
    echo "${FG_RED}ERR${RESET}[${date}] $msg" >&2
}


set_colors()

while [ $# -gt 0 ]
do
	key="${1}"
	case ${key} in
	-d|--directory)
		shift
		BASE=$1
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)    # unknown option
		log_err "Unknown argument ${key}."
		usage
		exit 1
		;;
	esac
done

BASE=$(realpath "$BASE")

DATA_DIR="$BASE/data"

LOG_DIR="$BASE/logs/"

CONFIG_DIR="$BASE/config"
CONFIG_FILE="$BASE/dev.yaml"
CSCLI_DIR="$CONFIG_DIR/crowdsec-cli"
PARSER_DIR="$CONFIG_DIR/parsers"
PARSER_S00="$PARSER_DIR/s00-raw"
PARSER_S01="$PARSER_DIR/s01-parse"
PARSER_S02="$PARSER_DIR/s02-enrich"
SCENARIOS_DIR="$CONFIG_DIR/scenarios"
POSTOVERFLOWS_DIR="$CONFIG_DIR/postoverflows"
HUB_DIR="$CONFIG_DIR/hub"
PLUGINS="http slack splunk email"
PLUGINS_DIR="plugins"
NOTIF_DIR="notifications"


create_tree() {
	mkdir -p "$BASE"
	mkdir -p "$DATA_DIR"
	mkdir -p "$LOG_DIR"
	mkdir -p "$CONFIG_DIR"
	mkdir -p "$PARSER_DIR"
	mkdir -p "$PARSER_S00"
	mkdir -p "$PARSER_S01"
	mkdir -p "$PARSER_S02"
	mkdir -p "$SCENARIOS_DIR"
	mkdir -p "$POSTOVERFLOWS_DIR"
	mkdir -p "$CSCLI_DIR"
	mkdir -p "$HUB_DIR"
	mkdir -p "$CONFIG_DIR/$NOTIF_DIR/$plugin"
	mkdir -p "$BASE/$PLUGINS_DIR"
}

copy_files() {
	cp "./config/profiles.yaml" "$CONFIG_DIR"
	cp "./config/simulation.yaml" "$CONFIG_DIR"
	cp "./cmd/crowdsec/crowdsec" "$BASE"
	cp "./cmd/crowdsec-cli/cscli" "$BASE"
	cp -r "./config/patterns" "$CONFIG_DIR"
	cp "./config/acquis.yaml" "$CONFIG_DIR"
	touch "$CONFIG_DIR"/local_api_credentials.yaml
	touch "$CONFIG_DIR"/online_api_credentials.yaml
	envsubst < "./config/dev.yaml" > "$BASE/dev.yaml"
	for plugin in $PLUGINS; do
		cp "$PLUGINS_DIR/$NOTIF_DIR/$plugin/notification-$plugin" "$BASE/$PLUGINS_DIR/notification-$plugin"
		cp "$PLUGINS_DIR/$NOTIF_DIR/$plugin/$plugin.yaml" "$CONFIG_DIR/$NOTIF_DIR/$plugin.yaml"
	done
}


setup() {
	"$BASE/cscli" -c "$CONFIG_FILE" hub update
	"$BASE/cscli" -c "$CONFIG_FILE" collections install crowdsecurity/linux
}

setup_api() {
	"$BASE/cscli" -c "$CONFIG_FILE" machines add test -p testpassword -f "$CONFIG_DIR/local_api_credentials.yaml" --force
}


main() {
	log_info "Creating directory tree in $BASE"
	create_tree
	log_info "Directory tree created"
	log_info "Copying needed files for tests environment"
	copy_files
	log_info "Files copied"
	log_info "Setting up configurations"
	CURRENT_PWD=$(pwd)
	cd "$BASE"
	setup_api
	setup
	cd "$CURRENT_PWD"
	log_info "Environment is ready in $BASE"
}


main
