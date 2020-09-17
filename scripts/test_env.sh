#!/bin/bash

BASE="./tests"

while [[ $# -gt 0 ]]
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
		log_err "Unknown argument ${key}."
		usage
		exit 1
		;;
	esac
done

BASE=$(realpath $BASE)

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

log_info() {
	msg=$1
	date=$(date +%x:%X)
	echo -e "[$date][INFO] $msg"
}

create_arbo() {
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
}

copy_files() {
	cp "./config/profiles.yaml" "$CONFIG_DIR"
	cp "./config/dev.yaml" "$BASE"
	cp  "./config/simulation.yaml" "$CONFIG_DIR"
	cp "./cmd/crowdsec/crowdsec" "$BASE"
	cp "./cmd/crowdsec-cli/cscli" "$BASE"
	cp -r "./config/patterns" "$CONFIG_DIR"
}


setup() {
	$BASE/cscli -c "$CONFIG_FILE" update
	$BASE/cscli -c "$CONFIG_FILE" install collection crowdsecurity/linux
}


main() {
	log_info "Creating test arboresence in $BASE"
	create_arbo
	log_info "Arboresence created"
	log_info "Copying needed files for tests environment"
	copy_files
	log_info "Files copied"
	log_info "Setting up configurations"
	CURRENT_PWD=$(pwd)
	cd $BASE
	setup
	cd $CURRENT_PWD
	log_info "Environment is ready in $BASE"
}



usage() {
	  echo "Usage:"
	  echo "    ./wizard.sh -h                               Display this help message."
	  echo "    ./env_test.sh -d ./tests                     Create test environment in './tests' folder"
	  exit 0  
}



main
