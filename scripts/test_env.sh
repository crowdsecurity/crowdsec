#!/bin/sh

set -eu

BASE="./tests"

usage() {
	echo "Usage:"
	echo "    $0 -h                             Display this help message."
	echo "    $0 -d ./tests                     Create test environment in './tests' folder"
}


while [ $# -gt 0 ]
do
	key="${1}"
	case ${key} in
	-d|--directory)
		BASE=${2}
		shift #past argument
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)    # unknown option
		echo "Unknown argument ${key}." >&2
		usage
		exit 1
		;;
	esac
done

BASE=$(realpath "$BASE")

DATA_DIR="$BASE/data"

CONFIG_DIR="$BASE/config"
CONFIG_FILE="$BASE/dev.yaml"
HUB_DIR="$CONFIG_DIR/hub"
PLUGINS="http slack splunk email sentinel file"
PLUGINS_DIR="$BASE/plugins"
NOTIF_DIR="notifications"

log_info() {
	msg=$1
	date=$(date +%x:%X)
	echo "[$date][INFO] $msg"
}

create_tree() {
	mkdir -p "$BASE"
	mkdir -p "$DATA_DIR"
	mkdir -p "$BASE/logs/"
	mkdir -p "$CONFIG_DIR"
	mkdir -p "$HUB_DIR"
	mkdir -p "$CONFIG_DIR/$NOTIF_DIR"
	mkdir -p "$PLUGINS_DIR"
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

	# shellcheck disable=SC2016
	CONFIG_DIR="$CONFIG_DIR" DATA_DIR="$DATA_DIR" PLUGINS_DIR="$PLUGINS_DIR" envsubst '$CONFIG_DIR $DATA_DIR $PLUGINS_DIR' < "./config/dev.yaml" > "$BASE/dev.yaml"

	for plugin in $PLUGINS; do
		cp "cmd/notification-$plugin/notification-$plugin" "$PLUGINS_DIR/notification-$plugin"
		cp "cmd/notification-$plugin/$plugin.yaml" "$CONFIG_DIR/$NOTIF_DIR/$plugin.yaml"
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
	log_info "Creating test tree in $BASE"
	create_tree
	log_info "Tree created"
	log_info "Copying needed files for tests environment"
	copy_files
	log_info "Files copied"
	log_info "Setting up configurations"
	CURRENT_PWD=$(pwd)
	cd "$BASE" || exit 2
	setup_api
	setup
	cd "$CURRENT_PWD" || exit 2
	log_info "Environment is ready in $BASE"
}

main
