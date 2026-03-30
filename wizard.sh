#!/usr/bin/env sh

RED=$(printf '\033[0;31m')
BLUE=$(printf '\033[0;34m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[1;33m')
ORANGE=$(printf '\033[0;33m')
NC=$(printf '\033[0m')

DOCKER_MODE="false"

CROWDSEC_LIB_DIR="/var/lib/crowdsec"
CROWDSEC_USR_DIR="/usr/local/lib/crowdsec"
CROWDSEC_DATA_DIR="${CROWDSEC_LIB_DIR}/data"
CROWDSEC_CONFIG_DIR="/etc/crowdsec"
CROWDSEC_PLUGIN_DIR="${CROWDSEC_USR_DIR}/plugins"

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

SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec.service"

PATTERNS_FOLDER="config/patterns"
PATTERNS_PATH="$CROWDSEC_CONFIG_DIR"/patterns/

ACTION=""

DEBUG_MODE="false"
FORCE_MODE="false"

PLUGINS="http slack splunk email sentinel file"

log_info() {
    msg=$1
    date=$(date "+%Y-%m-%d %H:%M:%S")
    echo "${BLUE}INFO${NC}[${date}] crowdsec_wizard: ${msg}" >&2
}

log_fatal() {
    msg=$1
    date=$(date "+%Y-%m-%d %H:%M:%S")
    echo "${RED}FATA${NC}[${date}] crowdsec_wizard: ${msg}" >&2
    exit 1
}

log_warn() {
    msg=$1
    date=$(date "+%Y-%m-%d %H:%M:%S")
    echo "${ORANGE}WARN${NC}[${date}] crowdsec_wizard: ${msg}" >&2
}

log_err() {
    msg=$1
    date=$(date "+%Y-%m-%d %H:%M:%S")
    echo "${RED}ERR${NC}[${date}] crowdsec_wizard: ${msg}" >&2
}

log_dbg() {
    if [ "$DEBUG_MODE" = "true" ]; then
        msg=$1
        date=$(date "+%Y-%m-%d %H:%M:%S")
        echo "[${date}][${YELLOW}DBG${NC}] crowdsec_wizard: ${msg}" >&2
    fi
}

detect_cs_install () {
    if [ -f "$CROWDSEC_BIN_INSTALLED" ]; then
        log_warn "Crowdsec is already installed !"
        echo ""
        echo "We recommend to upgrade : sudo ./wizard.sh --upgrade "
        echo "If you want to install it anyway, please use '--force'."
        echo ""
        echo "Run : sudo ./wizard.sh -i --force"
        if [ "$FORCE_MODE" = "false" ]; then
            exit 1
        fi
    fi
}

check_cs_version () {
    CURRENT_CS_VERSION=$(crowdsec -version 2>&1 | grep version | grep -Eio 'v[0-9]+.[0-9]+.[0-9]+' | cut -c 2-)
    NEW_CS_VERSION=$($CROWDSEC_BIN -version 2>&1 | grep version | grep -Eio 'v[0-9]+.[0-9]+.[0-9]+' | cut -c 2-)
    CURRENT_MAJOR_VERSION=$(echo "$CURRENT_CS_VERSION" | cut -d'.' -f1)
    CURRENT_MINOR_VERSION=$(echo "$CURRENT_CS_VERSION" | cut -d'.' -f2)
    CURRENT_PATCH_VERSION=$(echo "$CURRENT_CS_VERSION" | cut -d'.' -f3)
    NEW_MAJOR_VERSION=$(echo "$NEW_CS_VERSION" | cut -d'.' -f1)
    NEW_MINOR_VERSION=$(echo "$NEW_CS_VERSION" | cut -d'.' -f2)
    NEW_PATCH_VERSION=$(echo "$NEW_CS_VERSION" | cut -d'.' -f3)

    if [ "$NEW_MAJOR_VERSION" -gt "$CURRENT_MAJOR_VERSION" ]; then
        if [ "$FORCE_MODE" = "false" ]; then
            log_warn "new version ($NEW_CS_VERSION) is a major, you should follow documentation to upgrade !"
            echo ""
            exit 1
        fi
    elif [ "$NEW_MINOR_VERSION" -gt "$CURRENT_MINOR_VERSION" ]; then
        log_warn "new version ($NEW_CS_VERSION) is a minor upgrade !"
        if [ "$ACTION" != "upgrade" ]; then
            if [ "$FORCE_MODE" = "false" ]; then
                echo ""
                echo "We recommend to upgrade with : sudo ./wizard.sh --upgrade "
                echo "If you want to $ACTION anyway, please use '--force'."
                echo ""
                echo "Run : sudo ./wizard.sh --$ACTION --force"
                exit 1
            fi
        fi
    elif [ "$NEW_PATCH_VERSION" -gt "$CURRENT_PATCH_VERSION" ] ; then
        log_warn "new version ($NEW_CS_VERSION) is a patch !"
        if [ "$ACTION" != "binupgrade" ] ; then
            if [ "$FORCE_MODE" = "false" ]; then
                echo ""
                echo "We recommend to upgrade binaries only : sudo ./wizard.sh --binupgrade "
                echo "If you want to $ACTION anyway, please use '--force'."
                echo ""
                echo "Run : sudo ./wizard.sh --$ACTION --force"
                exit 1
            fi
        fi
    elif [ "$NEW_MINOR_VERSION" -eq "$CURRENT_MINOR_VERSION" ]; then
        log_warn "new version ($NEW_CS_VERSION) is same as current version ($CURRENT_CS_VERSION) !"
        if [ "$FORCE_MODE" = "false" ]; then
            echo ""
            echo "We recommend to $ACTION only if it's an higher version. "
            echo "If it's an RC version (vX.X.X-rc) you can upgrade it using '--force'."
            echo ""
            echo "Run : sudo ./wizard.sh --$ACTION --force"
            exit 1
        fi
    fi
}

# install crowdsec and cscli
install_crowdsec() {
    mkdir -p "${CROWDSEC_DATA_DIR}"
    (cd config && find patterns -type f -exec install -Dm 644 "{}" "$CROWDSEC_CONFIG_DIR/{}" \; && cd ../) || exit
    mkdir -p "$CROWDSEC_CONFIG_DIR"/acquis.d || exit

    mkdir -p /etc/crowdsec/hub/

    # Don't overwrite existing files
    [ ! -f "$CROWDSEC_CONFIG_DIR/$CLIENT_SECRETS" ] && install -v -m 600 -D "./config/$CLIENT_SECRETS" "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR/$LAPI_SECRETS" ]   && install -v -m 600 -D "./config/$LAPI_SECRETS"   "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR"/config.yaml ]     && install -v -m 600 -D ./config/config.yaml       "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR"/dev.yaml ]        && install -v -m 644 -D ./config/dev.yaml          "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR"/user.yaml ]       && install -v -m 644 -D ./config/user.yaml         "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR"/acquis.yaml ]     && install -v -m 644 -D ./config/acquis.yaml       "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR"/profiles.yaml ]   && install -v -m 644 -D ./config/profiles.yaml     "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR"/simulation.yaml ] && install -v -m 644 -D ./config/simulation.yaml   "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_CONFIG_DIR"/console.yaml ]    && install -v -m 644 -D ./config/console.yaml      "$CROWDSEC_CONFIG_DIR" >/dev/null || exit
    [ ! -f "$CROWDSEC_DATA_DIR"/detect.yaml ]       && install -v -m 600 -D ./config/detect.yaml       "$CROWDSEC_DATA_DIR" >/dev/null || exit

    # shellcheck disable=SC2016
    DATA="$CROWDSEC_DATA_DIR" CFG="$CROWDSEC_CONFIG_DIR" envsubst '$CFG $DATA' < ./config/user.yaml > "$CROWDSEC_CONFIG_DIR"/user.yaml || log_fatal "unable to generate user configuration file"
    if [ "$DOCKER_MODE" = "false" ]; then
        # shellcheck disable=SC2016
        CFG="$CROWDSEC_CONFIG_DIR" BIN="$CROWDSEC_BIN_INSTALLED" envsubst '$CFG $BIN' < ./config/crowdsec.service > "${SYSTEMD_PATH_FILE}" || log_fatal "unable to crowdsec systemd file"
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
        log_err "Crowdsec binary '$CROWDSEC_BIN' not found. Please build it with 'make build'" && exit
    fi
    if [ ! -f "$CSCLI_BIN" ]; then
        log_err "Cscli binary '$CSCLI_BIN' not found. Please build it with 'make build'" && exit
    fi

    log_info "Removing old binaries"
    uninstall_crowdsec
    log_info "Installing crowdsec"
    install_crowdsec
    log_info "Updating hub"
    ${CSCLI_BIN_INSTALLED} hub update
    log_info "Finished, restarting"
    systemctl restart crowdsec || log_fatal "Failed to restart crowdsec"
}

install_bins() {
    log_dbg "Installing crowdsec binaries"
    install -v -m 755 -D "$CROWDSEC_BIN" "$CROWDSEC_BIN_INSTALLED" >/dev/null || exit
    install -v -m 755 -D "$CSCLI_BIN" "$CSCLI_BIN_INSTALLED" >/dev/null || exit
    if command -v systemctl >/dev/null && systemctl is-active --quiet crowdsec; then
        systemctl stop crowdsec
    fi
    install_plugins
    symlink_bins
}

symlink_bins() {
    if (echo "$PATH" | grep -q "$BIN_INSTALL_PATH"); then
        log_dbg "$BIN_INSTALL_PATH found in PATH"
    else
        ln -s "$CSCLI_BIN_INSTALLED" /usr/bin/cscli
        ln -s "$CROWDSEC_BIN_INSTALLED" /usr/bin/crowdsec
    fi
}

delete_bins() {
    log_info "Removing crowdsec binaries"
    rm -f "$CROWDSEC_BIN_INSTALLED"
    rm -f "$CSCLI_BIN_INSTALLED"
}

delete_plugins() {
    rm -rf "$CROWDSEC_PLUGIN_DIR"
}

install_plugins() {
    mkdir -p "$CROWDSEC_PLUGIN_DIR"
    mkdir -p /etc/crowdsec/notifications

    for name in $PLUGINS; do
        bin="./cmd/notification-${name}/notification-${name}"
        conf="./cmd/notification-${name}/${name}.yaml"
        install -m 755 -D "$bin" "$CROWDSEC_PLUGIN_DIR"
        [ ! -e "/etc/crowdsec/notifications/${name}.yaml" ] && install -m 600 "$conf" "/etc/crowdsec/notifications/"
    done
}

check_running_bouncers() {
    # when uninstalling, check if user still has bouncers
    BOUNCERS_COUNT=$(${CSCLI_BIN} bouncers list -o=raw | tail -n +2 | wc -l)
    if [ "$BOUNCERS_COUNT" -gt 0 ] ; then
        if [ "$FORCE_MODE" = "false" ]; then
            echo "WARNING : You have at least one bouncer registered (cscli bouncers list)."
            echo "WARNING : Uninstalling crowdsec with a running bouncer will let it in an unpredictable state."
            echo "WARNING : If you want to uninstall crowdsec, you should first uninstall the bouncers."
            echo "Specify --force to bypass this restriction."
            exit 1
        fi;
    fi
}

# uninstall crowdsec and cscli
uninstall_crowdsec() {
    systemctl stop crowdsec.service >/dev/null
    systemctl disable -q crowdsec.service >/dev/null
    delete_bins

    rm -rf "$CROWDSEC_USR_DIR" || echo ""
    rm -f "$SYSTEMD_PATH_FILE" || echo ""
    log_info "crowdsec successfully uninstalled"
}


show_link() {
    echo ""
    echo "Useful links to start with Crowdsec:"
    echo ""
    echo "  - Documentation : https://doc.crowdsec.net/docs/getting_started/crowdsec_tour"
    echo "  - Crowdsec Hub  : https://hub.crowdsec.net/ "
    echo "  - Open issues   : https://github.com/crowdsecurity/crowdsec/issues"
    echo ""
    echo "Useful commands to start with Crowdsec:"
    echo ""
    echo "  - sudo cscli metrics             : https://doc.crowdsec.net/docs/observability/cscli"
    echo "  - sudo cscli decisions list      : https://doc.crowdsec.net/docs/user_guides/decisions_mgmt"
    echo "  - sudo cscli hub list            : https://doc.crowdsec.net/docs/user_guides/hub_mgmt"
    echo ""
    echo "Next step:  visualize all your alerts and explore our community CTI : https://app.crowdsec.net"
    echo ""
}

main() {
    if [ "$1" = "install" ] || [ "$1" = "configure" ]; then
        if ! command -v envsubst >/dev/null; then
            log_fatal "envsubst binary is needed to use do a full install with the wizard, exiting ..."
        fi
    fi

    if [ "$(id -u)" != "0" ]; then
        log_err "Please run the wizard as root or with sudo"
        exit 1
    fi

    if [ "$1" = "binupgrade" ];
    then
        check_cs_version
        update_bins
        return
    fi

    if [ "$1" = "upgrade" ];
    then
        check_cs_version
        update_full
        return
    fi

    if [ "$1" = "configure" ];
    then
        ${CSCLI_BIN_INSTALLED} hub update --error || (log_err "fail to update crowdsec hub. exiting" && exit 1)
        ${CSCLI_BIN_INSTALLED} setup interactive

        return
    fi

    if [ "$1" = "uninstall" ];
    then
        check_running_bouncers
        uninstall_crowdsec
        return
    fi

    if [ "$1" = "bininstall" ];
    then
        log_info "checking existing crowdsec install"
        detect_cs_install
        log_info "installing crowdsec"
        install_crowdsec

        show_link
        return
    fi

    if [ "$1" = "install" ];
    then
        log_info "checking if crowdsec is installed"
        detect_cs_install
        ## Do make build before installing (as non--root) in order to have the binary and then install crowdsec as root
        log_info "installing crowdsec"
        install_crowdsec
        log_dbg "configuring ${CSCLI_BIN_INSTALLED}"

        ${CSCLI_BIN_INSTALLED} hub update --error || (log_err "fail to update crowdsec hub. exiting" && exit 1)
        ${CSCLI_BIN_INSTALLED} setup interactive

        # install patterns/ folder
        log_dbg "Installing patterns"
        mkdir -p "${PATTERNS_PATH}"
        cp "./${PATTERNS_FOLDER}/"* "${PATTERNS_PATH}/"

        # api register
        ${CSCLI_BIN_INSTALLED} machines add --force "$(cat /etc/machine-id)" -a -f "$CROWDSEC_CONFIG_DIR/$CLIENT_SECRETS" || log_fatal "unable to add machine to the local API"
        log_dbg "Crowdsec LAPI registered"

        ${CSCLI_BIN_INSTALLED} capi register --error || log_fatal "unable to register to the Central API"

        systemctl enable -q crowdsec >/dev/null || log_fatal "unable to enable crowdsec"
        systemctl start crowdsec >/dev/null || log_fatal "unable to start crowdsec"
        log_info "enabling and starting crowdsec daemon"
        show_link
        return
    fi

    if [ "$1" = "unattended" ];
    then
        log_info "checking if crowdsec is installed"
        detect_cs_install
        ## Do make build before installing (as non--root) in order to have the binary and then install crowdsec as root
        log_info "installing crowdsec"
        install_crowdsec
        log_dbg "configuring ${CSCLI_BIN_INSTALLED}"

        ${CSCLI_BIN_INSTALLED} hub update --error || (log_err "fail to update crowdsec hub. exiting" && exit 1)
        ${CSCLI_BIN_INSTALLED} setup unattended

        # install patterns/ folder
        log_dbg "Installing patterns"
        mkdir -p "${PATTERNS_PATH}"
        cp "./${PATTERNS_FOLDER}/"* "${PATTERNS_PATH}/"

        # api register
        ${CSCLI_BIN_INSTALLED} machines add --force "$(cat /etc/machine-id)" -a -f "$CROWDSEC_CONFIG_DIR/$CLIENT_SECRETS" || log_fatal "unable to add machine to the local API"
        log_dbg "Crowdsec LAPI registered"

        ${CSCLI_BIN_INSTALLED} capi register --error || log_fatal "unable to register to the Central API"

        systemctl enable -q crowdsec >/dev/null || log_fatal "unable to enable crowdsec"
        systemctl start crowdsec >/dev/null || log_fatal "unable to start crowdsec"
        log_info "enabling and starting crowdsec daemon"
        show_link
        return
    fi
}

usage() {
      echo "Usage:"
      echo "    ./wizard.sh -h                               Display this help message."
      echo "    ./wizard.sh -i|--install                     Assisted installation of crowdsec/cscli and collections"
      echo "    ./wizard.sh -c|--configure                   Reconfigure collections and acquisition"
      echo "    ./wizard.sh --bininstall                     Install binaries and empty config, no wizard."
      echo "    ./wizard.sh --uninstall                      Uninstall crowdsec/cscli"
      echo "    ./wizard.sh --binupgrade                     Upgrade crowdsec/cscli binaries"
      echo "    ./wizard.sh --upgrade                        Perform a full upgrade and try to migrate configs"
      echo "    ./wizard.sh --unattended                     Install in unattended mode, no question will be asked and defaults will be followed"
      echo "    ./wizard.sh --docker-mode                    Will install crowdsec without systemd and generate random machine-id"
}

if [ $# -eq 0 ]; then
    usage
    exit 0
fi

while [ $# -gt 0 ]
do
    key="${1}"
    case ${key} in
    --uninstall)
        ACTION="uninstall"
        shift # past argument
        ;;
    --binupgrade)
        ACTION="binupgrade"
        shift # past argument
        ;;
    --upgrade)
        ACTION="upgrade"
        shift # past argument
        ;;
    -i|--install)
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
    -c|--configure)
        ACTION="configure"
        shift # past argument
        ;;
    --unattended)
        ACTION="unattended"
        shift # past argument
        ;;
    -f|--force)
        FORCE_MODE="true"
        shift
        ;;
    -v|--verbose)
        DEBUG_MODE="true"
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

main "$ACTION"
