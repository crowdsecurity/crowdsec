#!/bin/sh

# allow calling functions in an "if" statement
#shellcheck disable=SC2310

set -e

checkroot() {
    #shellcheck disable=SC2312
    if [ "$(id -u)" -ne 0 ]; then
        log_err "Please run the wizard as root or with sudo"
        exit 1
    fi
}

interactive() {
    if [ ! -t 0 ] || [ "$SILENT" = "true" ]; then
        return 1
    fi
    return 0
}

SILENT="false"
DOCKER_MODE="false"

CROWDSEC_LIB_DIR="/var/lib/crowdsec"
CROWDSEC_USR_DIR="/usr/local/lib/crowdsec"
CROWDSEC_DATA_DIR="${CROWDSEC_LIB_DIR}/data"
CROWDSEC_DB_PATH="${CROWDSEC_DATA_DIR}/crowdsec.db"
CROWDSEC_PATH="/etc/crowdsec"
CROWDSEC_CONFIG_PATH="$CROWDSEC_PATH"
CROWDSEC_LOG_FILE="/var/log/crowdsec.log"
LAPI_LOG_FILE="/var/log/crowdsec_api.log"

CROWDSEC_BIN="./cmd/crowdsec/crowdsec"
CSCLI_BIN="./cmd/crowdsec-cli/cscli"

CLIENT_SECRETS="local_api_credentials.yaml"
LAPI_SECRETS="online_api_credentials.yaml"

BIN_INSTALL_PATH="/usr/local/bin"
CROWDSEC_BIN_INSTALLED="${BIN_INSTALL_PATH}/crowdsec"

if [ -f "/usr/bin/cscli" ]; then
    CSCLI_BIN_INSTALLED="/usr/bin/cscli"
else
    CSCLI_BIN_INSTALLED="${BIN_INSTALL_PATH}/cscli"
fi

ACQUIS_DIR="${CROWDSEC_CONFIG_PATH}/acquis.d"
ACQUIS_YAML="${CROWDSEC_CONFIG_PATH}/acquis.yaml"

SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec.service"

PATTERNS_FOLDER="config/patterns"
PATTERNS_PATH="${CROWDSEC_CONFIG_PATH}/patterns/"

ACTION=""

DEBUG_MODE="false"
FORCE_MODE="false"

PLUGIN_CONFIGURATION_SRC="./plugins/notifications"
PLUGIN_CONFIGURATION_DEST="/etc/crowdsec/notifications"
PLUGIN_BINARIES_SRC="./plugins/notifications"
PLUGIN_BINARIES_DEST="${CROWDSEC_USR_DIR}/plugins"

# XXX WTH should remove it later
BACKUP_DIR=$(mktemp -d)
rm -rf -- "$BACKUP_DIR"

set_colors() {
    #shellcheck disable=SC2034
    if [ ! -t 0 ]; then
        # terminal is not interactive; no colors
        FG_RED=""
        FG_GREEN=""
        FG_YELLOW=""
        FG_BLUE=""
        FG_MAGENTA=""
        FG_CYAN=""
        FG_WHITE=""
        BOLD=""
        RESET=""
    elif tput sgr0 >/dev/null; then
        # terminfo
        FG_RED=$(tput setaf 1)
        FG_GREEN=$(tput setaf 2)
        FG_YELLOW=$(tput setaf 3)
        FG_BLUE=$(tput setaf 4)
        FG_MAGENTA=$(tput setaf 5)
        FG_CYAN=$(tput setaf 6)
        FG_WHITE=$(tput setaf 7)
        BOLD=$(tput bold)
        RESET=$(tput sgr0)
    else
        FG_RED=$(printf '%b' '\033[31m')
        FG_GREEN=$(printf '%b' '\033[32m')
        FG_YELLOW=$(printf '%b' '\033[33m')
        FG_BLUE=$(printf '%b' '\033[34m')
        FG_MAGENTA=$(printf '%b' '\033[35m')
        FG_CYAN=$(printf '%b' '\033[36m')
        FG_WHITE=$(printf '%b' '\033[37m')
        BOLD=$(printf '%b' '\033[1m')
        RESET=$(printf '%b' '\033[0m')
    fi
}

#XXX logging is not consistent
log_info() {
    msg=$1
    date=$(date +%x:%X)
    echo "${FG_BLUE}INFO${RESET}[${date}] crowdsec_wizard: ${msg}"
}

log_fatal() {
    msg=$1
    date=$(date +%x:%X)
    echo "${FG_RED}FATA${RESET}[${date}] crowdsec_wizard: ${msg}" >&2
    exit 1
}

log_warn() {
    msg=$1
    date=$(date +%x:%X)
    echo "${FG_YELLOW}WARN${RESET}[${date}] crowdsec_wizard: ${msg}"
}

log_err() {
    msg=$1
    date=$(date +%x:%X)
    echo "${FG_RED}ERR${RESET}[${date}] crowdsec_wizard: ${msg}" >&2
}

log_dbg() {
    if [ "$DEBUG_MODE" = "true" ]; then
        msg=$1
        date=$(date +%x:%X)
        echo "[${date}][${FG_YELLOW}DBG${RESET}] crowdsec_wizard: ${msg}" >&2
    fi
}

crowdsec_service_stop() {
    if command -v systemctl >/dev/null && systemctl is-active --quiet crowdsec; then
        systemctl stop crowdsec.service
    fi
}

crowdsec_service_disable() {
    if command -v systemctl >/dev/null && systemctl is-enabled --quiet crowdsec; then
        systemctl disable crowdsec.service
    fi
}

crowdsec_service_restart() {
    if command -v systemctl >/dev/null; then
        systemctl restart crowdsec
    fi
}


detect_cs_install() {
    if [ -f "$CROWDSEC_BIN_INSTALLED" ]; then
        log_warn "Crowdsec is already installed!"
        echo ""
        echo "We recommend to upgrade: sudo $0 --upgrade "
        echo "If you want to install it anyway, please use '--force'."
        echo ""
        echo "Run: sudo $0 -i --force"
        if [ "$FORCE_MODE" = "false" ]; then
            exit 1
        fi
    fi
}

check_cs_version() {
    CURRENT_CS_VERSION=$(crowdsec -version 2>&1 | grep version | grep -Eio 'v[0-9]+.[0-9]+.[0-9]+' | cut -c 2-)
    NEW_CS_VERSION=$("$CROWDSEC_BIN" -version 2>&1 | grep version | grep -Eio 'v[0-9]+.[0-9]+.[0-9]+' | cut -c 2-)
    CURRENT_MAJOR_VERSION=$(echo "$CURRENT_CS_VERSION" | cut -d'.' -f1)
    CURRENT_MINOR_VERSION=$(echo "$CURRENT_CS_VERSION" | cut -d'.' -f2)
    CURRENT_PATCH_VERSION=$(echo "$CURRENT_CS_VERSION" | cut -d'.' -f3)
    NEW_MAJOR_VERSION=$(echo "$NEW_CS_VERSION" | cut -d'.' -f1)
    NEW_MINOR_VERSION=$(echo "$NEW_CS_VERSION" | cut -d'.' -f2)
    NEW_PATCH_VERSION=$(echo "$NEW_CS_VERSION" | cut -d'.' -f3)

    if [ "$NEW_MAJOR_VERSION" -gt "$CURRENT_MAJOR_VERSION" ]; then
        if [ "$FORCE_MODE" = "false" ]; then
            log_warn "new version (${NEW_CS_VERSION}) is a major, please follow the documentation to upgrade!"
            echo ""
            exit 1
        fi
    elif [ "$NEW_MINOR_VERSION" -gt "$CURRENT_MINOR_VERSION" ]; then
        log_warn "new version (${NEW_CS_VERSION}) is a minor upgrade!"
        if [ "$ACTION" != "upgrade" ]; then
            if [ "$FORCE_MODE" = "false" ]; then
                echo ""
                echo "We recommend to upgrade with: sudo $0 --upgrade"
                echo "If you want to ${ACTION} anyway, please use '--force'."
                echo ""
                echo "Run: sudo $0 --${ACTION} --force"
                exit 1
            fi
        fi
    elif [ "$NEW_PATCH_VERSION" -gt "$CURRENT_PATCH_VERSION" ]; then
        log_warn "new version (${NEW_CS_VERSION}) is a patch !"
        if [ "$ACTION" != "binupgrade" ]; then
            if [ "$FORCE_MODE" = "false" ]; then
                echo ""
                echo "We recommend to upgrade binaries only: sudo $0 --binupgrade"
                echo "If you want to ${ACTION} anyway, please use '--force'."
                echo ""
                echo "Run: sudo $0 --${ACTION} --force"
                exit 1
            fi
        fi
    elif [ "$NEW_MINOR_VERSION" -eq "$CURRENT_MINOR_VERSION" ]; then
        log_warn "new version (${NEW_CS_VERSION}) is same as current version (${CURRENT_CS_VERSION})!"
        if [ "$FORCE_MODE" = "false" ]; then
            echo ""
            echo "We recommend to ${ACTION} only if it's an higher version."
            echo "If it's an RC version (vX.X.X-rc) you can upgrade it using '--force'."
            echo ""
            echo "Run: sudo $0 --${ACTION} --force"
            exit 1
        fi
    fi
}

install_crowdsec() {
    mkdir -p "$CROWDSEC_DATA_DIR"
    mkdir -p "$CROWDSEC_CONFIG_PATH/collections"
    mkdir -p "$CROWDSEC_CONFIG_PATH/parsers"
    mkdir -p "$CROWDSEC_CONFIG_PATH/patterns"
    mkdir -p "$CROWDSEC_CONFIG_PATH/postoverflows"
    mkdir -p "$CROWDSEC_CONFIG_PATH/scenarios"
    (cd config && find patterns -maxdepth 1 -type f -exec install -m 0644 "{}" "${CROWDSEC_CONFIG_PATH}/{}" \; && cd ../)

    install -m 0600 "./config/$CLIENT_SECRETS" "$CROWDSEC_CONFIG_PATH"
    install -m 0600 "./config/$LAPI_SECRETS" "$CROWDSEC_CONFIG_PATH"

    install -m 0600 ./config/config.yaml "$CROWDSEC_CONFIG_PATH"
    install -m 0644 ./config/dev.yaml "$CROWDSEC_CONFIG_PATH"
    install -m 0644 ./config/user.yaml "$CROWDSEC_CONFIG_PATH"
    install -m 0644 ./config/profiles.yaml "$CROWDSEC_CONFIG_PATH"
    install -m 0644 ./config/simulation.yaml "$CROWDSEC_CONFIG_PATH"
    install -m 0644 ./config/console.yaml "$CROWDSEC_CONFIG_PATH"

    mkdir -p "$CROWDSEC_CONFIG_PATH/hub"
    install -m 0644 ./config/detect.yaml "${CROWDSEC_CONFIG_PATH}/hub"

    #shellcheck disable=SC2016
    DATA=${CROWDSEC_DATA_DIR} CFG=${CROWDSEC_CONFIG_PATH} envsubst '$CFG $DATA' <./config/user.yaml >"${CROWDSEC_CONFIG_PATH}/user.yaml" || log_fatal "unable to generate user configuration file"
    if [ "$DOCKER_MODE" = "false" ]; then
        #shellcheck disable=SC2016
        CFG=${CROWDSEC_CONFIG_PATH} BIN=${CROWDSEC_BIN_INSTALLED} envsubst '$CFG $BIN' <./config/crowdsec.service >"$SYSTEMD_PATH_FILE" || log_fatal "unable to generate systemd file"
    fi
    install_bins

    if [ "$DOCKER_MODE" = "false" ]; then
        systemctl daemon-reload
    fi
}

update_bins() {
    log_info "Only upgrading binaries"
    delete_bins
    install_bins
    log_info "Upgrade finished"
    systemctl restart crowdsec || log_fatal "unable to restart crowdsec with systemctl"
}

update_full() {
    if [ ! -f "$CROWDSEC_BIN" ]; then
        log_err "Crowdsec binary '${CROWDSEC_BIN}' not found. Please build it with 'make build'"
        exit
    fi
    if [ ! -f "$CSCLI_BIN" ]; then
        log_err "Cscli binary '${CSCLI_BIN}' not found. Please build it with 'make build'"
        exit
    fi

    log_info "Backing up existing configuration"
    "$CSCLI_BIN_INSTALLED" config backup "$BACKUP_DIR"
    log_info "Saving default database content if exist"
    if [ -f "/var/lib/crowdsec/data/crowdsec.db" ]; then
        cp /var/lib/crowdsec/data/crowdsec.db "${BACKUP_DIR}/crowdsec.db"
    fi
    log_info "Cleanup existing crowdsec configuration"
    uninstall_crowdsec
    log_info "Installing crowdsec"
    install_crowdsec
    log_info "Restoring configuration"
    "$CSCLI_BIN_INSTALLED" hub update
    "$CSCLI_BIN_INSTALLED" config restore "$BACKUP_DIR"
    log_info "Restoring saved database if exist"
    if [ -f "${BACKUP_DIR}/crowdsec.db" ]; then
        cp "${BACKUP_DIR}/crowdsec.db" /var/lib/crowdsec/data/crowdsec.db
    fi
    log_info "Finished, restarting"
    crowdsec_service_restart || log_fatal "Failed to restart crowdsec"
}

install_bins() {
    log_dbg "Installing crowdsec binaries"
    install -m 0755 "$CROWDSEC_BIN" "$CROWDSEC_BIN_INSTALLED" >/dev/null
    install -m 0755 "$CSCLI_BIN" "$CSCLI_BIN_INSTALLED" >/dev/null

    crowdsec_service_stop
    install_plugins
    symlink_bins
}

symlink_bins() {
    if echo "$PATH" | grep -q "$BIN_INSTALL_PATH"; then
        log_dbg "${BIN_INSTALL_PATH} found in PATH"
    else
        ln -s "$CSCLI_BIN_INSTALLED" /usr/bin/cscli
        ln -s "$CROWDSEC_BIN_INSTALLED" /usr/bin/crowdsec
    fi
}

delete_bins() {
    log_info "Removing crowdsec binaries"
    rm -f -- "$CROWDSEC_BIN_INSTALLED"
    rm -f -- "$CSCLI_BIN_INSTALLED"
}

delete_plugins() {
    rm -rf -- "$PLUGIN_BINARIES_DEST"
}

detect_only() {
    "$CSCLI_BIN_INSTALLED" setup detect --yaml
}

edit_file() {
    editor="$VISUAL"
    if [ "$editor" = "" ]; then
        #shellcheck disable=SC2153
        editor="$EDITOR"
    fi
    if [ "$editor" = "" ]; then
        if command -v nano >/dev/null; then
            editor="nano"
        elif command -v nano-tiny >/dev/null; then
            editor="nano-tiny"
        elif command -v vi >/dev/null; then
            editor="vi"
        else
            echo "No editor found"
            exit 1
        fi
    fi
    "$editor" "$1"
}

detect_edit_validate() {
    setup_yaml_path="$1"
    while true; do
        cat <<-EOT >"$setup_yaml_path"
	#
	# XXX detection timestamp, how to edit
	# blah blah blah
	#
	# Out of safety, we recommend installing the parser 'crowdsecurity/whitelists'.
	# It will prevent private IP addresses from being banned. It's an anti-lockout measure,
	# feel free to remove it any time.
	#
	
	EOT

        echo
        "$CSCLI_BIN_INSTALLED" setup detect --yaml | tee -a "$setup_yaml_path"

        #
        # If the user asked for --unattended, or the script is not interactive,
        # we use the detected setup without changes.
        #
        if ! interactive; then
            return 0
        fi

        printf '%s ' "Crowdsec has detected these services. Do you want to edit the list now? (Y/n)"
        read -r confirm

        if echo "$confirm" | grep -q '^[Nn]'; then
            return 0
        fi

        while true; do
            edit_file "$setup_yaml_path"

            if ! errors=$("$CSCLI_BIN_INSTALLED" setup validate "$setup_yaml_path" 2>/dev/null); then
                echo
                echo "The setup file has errors:"
                echo

                if [ "$errors" = "EOF" ]; then
                    errors="The file is empty. A 'setup:' section is required, even if it has no items."
                fi

                echo "$errors"
                echo
                printf '%s ' "[E]dit, [D]etect again, [Q]uit configuration? (E/d/q)"

                read -r confirm

                if echo "$confirm" | grep -q '^[Dd]'; then
                    break
                fi

                if echo "$confirm" | grep -q '^[Qq]'; then
                    rm -f "$setup_yaml_path"
                    return 1
                fi
            else
                return 0
            fi
        done
    done
}

# Pause until the user types <enter>
# unless the script is run in non-interactive mode.
ask_press_enter() {
    if ! interactive; then
        return 0
    fi

    printf "%s " "Press Enter to continue:" >&2
    read -r key
}

# Check if we can proceed with the automatic detection and hub + acquisition configuration.
# If the script is interactive, we ask the user for confirmation when it makes sense.
#
# arguments: none
# return: 0 if we can proceed with the configuration, 1 if we should skip it.
safe_to_configure() {
    # if "wizard.sh" is in ACQUIS_YAML, never detect
    if grep -q 'wizard.sh' "$ACQUIS_YAML" 2>/dev/null; then
        cat <<-EOT >&2
	
	A previous version of Crowdsec has detected the running services and put
	datasource configuration in the file $ACQUIS_YAML.
	
	In this version, the same information goes in $ACQUIS_DIR, one
	file per service.
	
	If you want to run the automated service detection again, please remove the
	relevant sections from $ACQUIS_YAML or rename the file, and run "$0 --configure"
	again.
	
	EOT

        ask_press_enter
        return 1
    fi

    # if acquis.yaml exists but has no wizard.sh, ask for confirmation (if
    # interactive) before detecting
    if [ -f "$ACQUIS_YAML" ]; then

        if ! interactive; then
            echo "Skipping automatic detection because $ACQUIS_YAML already exists." >&2
            echo "Run \"$0 --configure\" to detect the services again." >&2
            return 1
        fi

        cat <<-EOT >&2
	
	A previous version of Crowdsec was already configured.
	
	If you run the automated service detection now, it will create new acquisition
	directives in $ACQUIS_DIR, in addition to the ones already in $ACQUIS_YAML.
	
	When the configuration is done, please check the content of these files
	to avoid duplicate log locations.
	
	EOT

        printf '%s ' "Do you want to run the service detection now? (y/N)"
        read -r confirm

        if echo "$confirm" | grep -q '^[Nn]'; then
            return 1
        fi
    fi

    return 0
}


detect_and_install_hub() {
    if ! safe_to_configure; then
        return 1
    fi

    tmp_dir=$(mktemp -d)
    tmp_file="$tmp_dir/setup.yaml"

    if ! detect_edit_validate "$tmp_file"; then
        echo
        echo "Exiting crowdsec configuration, you can run it again with '$0 --configure'" >&2
        ask_press_enter

        rm -f "$tmp_file"
        rmdir "$tmp_dir"
        return 1
    fi

    echo "Installing hub objects...."
    "$CSCLI_BIN_INSTALLED" setup install-hub "$tmp_file"

    mkdir -p "$ACQUIS_DIR"

    echo "Generating acquisition files..."
    "$CSCLI_BIN_INSTALLED" setup datasources "$tmp_file" --to-dir "$ACQUIS_DIR"

    if [ ! -f "$ACQUIS_YAML" ]; then
	cat <<-EOT >"$ACQUIS_YAML"
	---
	# Your datasource configuration goes here.
	EOT
    fi

    echo "Done"

    rm -f "$tmp_file"
    rmdir "$tmp_dir"
}

install_plugins() {
    for plugin in email http slack splunk; do
        mkdir -p "$PLUGIN_BINARIES_DEST"
        install -m 0755 "$PLUGIN_BINARIES_SRC/$plugin/notification-$plugin" "$PLUGIN_BINARIES_DEST/"

        if [ "$DOCKER_MODE" = "false" ]; then
            if [ -f "$PLUGIN_CONFIGURATION_DEST/$plugin/$plugin.yaml" ]; then
                chmod 0600 "$PLUGIN_CONFIGURATION_DEST/$plugin/$plugin.yaml"
            else
                mkdir -p "$PLUGIN_CONFIGURATION_DEST/$plugin"
                install -m 0600 "$PLUGIN_CONFIGURATION_SRC/$plugin/$plugin.yaml" "$PLUGIN_CONFIGURATION_DEST/$plugin/$plugin.yaml"
            fi
        fi
    done
}

check_running_bouncers() {
    # when uninstalling, check if the user still has bouncers
    BOUNCERS_COUNT=$("$CSCLI_BIN" bouncers list -o=raw | tail -n +2 | wc -l)
    if [ "$BOUNCERS_COUNT" -gt 0 ]; then
        if [ "$FORCE_MODE" = "false" ]; then
            echo "WARNING: You have at least one bouncer registered (cscli bouncers list)."
            echo "WARNING: Uninstalling crowdsec with a running bouncer will leave it in an unpredictable state."
            echo "WARNING: If you want to uninstall crowdsec, you should first uninstall the bouncers."
            echo "Specify --force to bypass this restriction."
            exit 1
        fi
    fi
}

# uninstall crowdsec and cscli
uninstall_crowdsec() {
    crowdsec_service_stop
    crowdsec_service_disable
    # there is no way to know if the dashboard exists, so we have to ignore errors.
    log_info "Removing dashboard..."
    if "$CSCLI_BIN" dashboard remove -f -y; then
        log_info "...done."
    else
        log_warn "...dashboard removal failed."
    fi
    delete_bins

    rm -f -- "$CROWDSEC_LOG_FILE" "$LAPI_LOG_FILE" "$CROWDSEC_DB_PATH" "$SYSTEMD_PATH_FILE"
    rm -rf -- "$CROWDSEC_LIB_DIR" "$CROWDSEC_USR_DIR"
    log_info "crowdsec successfully uninstalled"
}

show_links() {
    cat <<-EOT
	
	Useful links to start with Crowdsec:
	
	  - Documentation : ${BOLD}https://doc.crowdsec.net/docs/getting_started/crowdsec_tour${RESET}
	  - Crowdsec Hub  : ${BOLD}https://hub.crowdsec.net/${RESET}
	  - Open issues   : https://github.com/crowdsecurity/crowdsec/issues
	
	Useful commands to start with Crowdsec:
	
	  - sudo cscli metrics        : https://doc.crowdsec.net/docs/observability/cscli
	  - sudo cscli decisions list : https://doc.crowdsec.net/docs/user_guides/decisions_mgmt
	  - sudo cscli hub list       : https://doc.crowdsec.net/docs/user_guides/hub_mgmt
	
	Next step: visualize all your alerts and explore our community CTI - ${BOLD}https://app.crowdsec.net${RESET}
	
	CrowdSec alone will ${FG_YELLOW}${BOLD}not${RESET} block any IP address. If you want to block them, you must use a bouncer.
	You can find them on ${BOLD}https://hub.crowdsec.net/browse/#bouncers${RESET}
	
	EOT
}

main() {
    if [ "$1" = "install" ] || [ "$1" = "configure" ] || [ "$1" = "detect" ]; then
        if ! command -v envsubst >/dev/null; then
            log_fatal "envsubst binary is needed to use do a full install with the wizard, exiting..."
        fi
    fi

    if [ "$1" = "binupgrade" ]; then
        checkroot
        check_cs_version
        update_bins
        return 0
    fi

    if [ "$1" = "upgrade" ]; then
        checkroot
        check_cs_version
        update_full
        return 0
    fi

    if [ "$1" = "configure" ]; then
        checkroot
        "$CSCLI_BIN_INSTALLED" hub update
        detect_and_install_hub
        crowdsec_service_restart
        show_links
        return 0
    fi

    if [ "$1" = "noop" ]; then
        return 0
    fi

    if [ "$1" = "uninstall" ]; then
        checkroot
        check_running_bouncers
        uninstall_crowdsec
        return 0
    fi

    if [ "$1" = "bininstall" ]; then
        checkroot
        log_info "checking existing crowdsec install"
        detect_cs_install
        log_info "installing crowdsec"
        install_crowdsec

        show_links
        return 0
    fi

    if [ "$1" = "install" ]; then
        checkroot
        log_info "checking if crowdsec is installed"
        detect_cs_install

        # Run "make release" before installing (as non-root) in order to have the binary and then install crowdsec as root

        log_info "installing crowdsec"
        install_crowdsec
        log_dbg "configuring ${CSCLI_BIN_INSTALLED}"

        if ! "$CSCLI_BIN_INSTALLED" hub update >/dev/null 2>&1; then
            log_err "fail to update crowdsec hub. exiting"
            exit 1
        fi

        "$CSCLI_BIN_INSTALLED" hub update

        # install patterns/ folder
        log_dbg "Installing patterns"
        mkdir -p "$PATTERNS_PATH"
        cp "./${PATTERNS_FOLDER}/"* "${PATTERNS_PATH}/"

        # register api
        "$CSCLI_BIN_INSTALLED" machines add --force "$(cat /etc/machine-id)" -a -f "${CROWDSEC_CONFIG_PATH}/${CLIENT_SECRETS}" || log_fatal "unable to add machine to the local API"
        log_dbg "Crowdsec LAPI registered"

        "$CSCLI_BIN_INSTALLED" capi register || log_fatal "unable to register to the Central API"
        log_dbg "Crowdsec CAPI registered"

        detect_and_install_hub

        systemctl enable -q crowdsec >/dev/null || log_fatal "unable to enable crowdsec"
        systemctl start crowdsec >/dev/null || log_fatal "unable to start crowdsec"
        log_info "enabling and starting crowdsec daemon"

        show_links
        return 0
    fi

    if [ "$1" = "detect" ]; then
        detect_only
    fi
}

usage() {
    echo "Usage:"
    echo "    ./wizard.sh -h                               Display this help message."
    echo "    ./wizard.sh -c|--configure                   Detect running services and install hub objects + acquis files"
    echo "    ./wizard.sh -d|--detect                      Detect running services and print the result"
    echo "    ./wizard.sh -i|--install                     Assisted installation of crowdsec/cscli and hub objects"
    echo "    ./wizard.sh --bininstall                     Install binaries and empty config, no wizard."
    echo "    ./wizard.sh --uninstall                      Uninstall crowdsec/cscli"
    echo "    ./wizard.sh --binupgrade                     Upgrade crowdsec/cscli binaries"
    echo "    ./wizard.sh --upgrade                        Perform a full upgrade and try to migrate configs"
    echo "    ./wizard.sh --unattended                     Install in unattended mode, no question will be asked and defaults will be followed"
    echo "    ./wizard.sh --docker-mode                    Will install crowdsec without systemd and generate random machine-id"
    echo "    ./wizard.sh -n|--noop                        Do nothing"
}

if [ $# -eq 0 ]; then
    usage
    exit 0
fi

while [ $# -gt 0 ]; do
    key="${1}"
    case ${key} in
    --uninstall)
        ACTION="uninstall"
        shift #past argument
        ;;
    --binupgrade)
        ACTION="binupgrade"
        shift #past argument
        ;;
    --upgrade)
        ACTION="upgrade"
        shift #past argument
        ;;
    -i | --install)
        ACTION="install"
        shift # past argument
        ;;
    --bininstall)
        ACTION="bininstall"
        shift # past argument
        ;;
    --docker-mode)
        DOCKER_MODE="true"
        ACTION="bininstall"
        shift # past argument
        ;;
    -c | --configure)
        ACTION="configure"
        shift # past argument
        ;;
    -d | --detect)
        ACTION="detect"
        shift # past argument
        ;;
    -n | --noop)
        ACTION="noop"
        shift # past argument
        ;;
    --unattended)
        SILENT="true"
        ACTION="install"
        shift
        ;;
    -f | --force)
        FORCE_MODE="true"
        shift
        ;;
    -v | --verbose)
        DEBUG_MODE="true"
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *) # unknown option
        log_err "Unknown argument ${key}."
        usage
        exit 1
        ;;
    esac
done

set_colors
main "$ACTION"
exit 0
