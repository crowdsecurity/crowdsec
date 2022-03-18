#!/usr/bin/env bash

set -o pipefail
#set -x


RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
NC='\033[0m'

SILENT="false"
DOCKER_MODE="false"

CROWDSEC_RUN_DIR="/var/run"
CROWDSEC_LIB_DIR="/var/lib/crowdsec"
CROWDSEC_USR_DIR="/usr/local/lib/crowdsec"
CROWDSEC_DATA_DIR="${CROWDSEC_LIB_DIR}/data"
CROWDSEC_DB_PATH="${CROWDSEC_DATA_DIR}/crowdsec.db"
CROWDSEC_PATH="/etc/crowdsec"
CROWDSEC_CONFIG_PATH="${CROWDSEC_PATH}"
CROWDSEC_LOG_FILE="/var/log/crowdsec.log"
LAPI_LOG_FILE="/var/log/crowdsec_api.log"
CROWDSEC_PLUGIN_DIR="${CROWDSEC_USR_DIR}/plugins"
CROWDSEC_CONSOLE_DIR="${CROWDSEC_PATH}/console"


CROWDSEC_BIN="./cmd/crowdsec/crowdsec"
CSCLI_BIN="./cmd/crowdsec-cli/cscli"

CLIENT_SECRETS="local_api_credentials.yaml"
LAPI_SECRETS="online_api_credentials.yaml"

CONSOLE_FILE="console.yaml"

BIN_INSTALL_PATH="/usr/local/bin"
CROWDSEC_BIN_INSTALLED="${BIN_INSTALL_PATH}/crowdsec"

if [[ -f "/usr/bin/cscli" ]] ; then
    CSCLI_BIN_INSTALLED="/usr/bin/cscli"
else
    CSCLI_BIN_INSTALLED="${BIN_INSTALL_PATH}/cscli"
fi

ACQUIS_PATH="${CROWDSEC_CONFIG_PATH}"
TMP_ACQUIS_FILE="tmp-acquis.yaml"
ACQUIS_TARGET="${ACQUIS_PATH}/acquis.yaml"

SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec.service"

PATTERNS_FOLDER="config/patterns"
PATTERNS_PATH="${CROWDSEC_CONFIG_PATH}/patterns/"

ACTION=""

DEBUG_MODE="false"
FORCE_MODE="false"

SUPPORTED_SERVICES='apache2
httpd
nginx
sshd
mysql
telnet
smb
'


HTTP_PLUGIN_BINARY="./plugins/notifications/http/notification-http"
SLACK_PLUGIN_BINARY="./plugins/notifications/slack/notification-slack"
SPLUNK_PLUGIN_BINARY="./plugins/notifications/splunk/notification-splunk"
EMAIL_PLUGIN_BINARY="./plugins/notifications/email/notification-email"

HTTP_PLUGIN_CONFIG="./plugins/notifications/http/http.yaml"
SLACK_PLUGIN_CONFIG="./plugins/notifications/slack/slack.yaml"
SPLUNK_PLUGIN_CONFIG="./plugins/notifications/splunk/splunk.yaml"
EMAIL_PLUGIN_CONFIG="./plugins/notifications/email/email.yaml"

BACKUP_DIR=$(mktemp -d)
rm -rf -- "$BACKUP_DIR"

log_info() {
    msg=$1
    date=$(date +%x:%X)
    echo -e "${BLUE}INFO${NC}[${date}] crowdsec_wizard: ${msg}"
}

log_fatal() {
    msg=$1
    date=$(date +%x:%X)
    echo -e "${RED}FATA${NC}[${date}] crowdsec_wizard: ${msg}" 1>&2 
    exit 1
}

log_warn() {
    msg=$1
    date=$(date +%x:%X)
    echo -e "${ORANGE}WARN${NC}[${date}] crowdsec_wizard: ${msg}"
}

log_err() {
    msg=$1
    date=$(date +%x:%X)
    echo -e "${RED}ERR${NC}[${date}] crowdsec_wizard: ${msg}" 1>&2
}

log_dbg() {
    if [[ ${DEBUG_MODE} == "true" ]]; then
        msg=$1
        date=$(date +%x:%X)
        echo -e "[${date}][${YELLOW}DBG${NC}] crowdsec_wizard: ${msg}" 1>&2
    fi
}

detect_services () {
    DETECTED_SERVICES=()
    HMENU=()
    #list systemd services
    SYSTEMD_SERVICES=`systemctl  --state=enabled list-unit-files '*.service' | cut -d ' ' -f1`
    #raw ps
    PSAX=`ps ax -o comm=`
    for SVC in ${SUPPORTED_SERVICES} ; do
        log_dbg "Checking if service '${SVC}' is running (ps+systemd)"
        for SRC in "${SYSTEMD_SERVICES}" "${PSAX}" ; do
            echo ${SRC} | grep ${SVC} >/dev/null
            if [ $? -eq 0 ]; then
                #on centos, apache2 is named httpd                                                                                                                                                                                            
                if [[ ${SVC} == "httpd" ]] ; then
                    SVC="apache2";
                fi
                DETECTED_SERVICES+=(${SVC})
                HMENU+=(${SVC} "on")
                log_dbg "Found '${SVC}' running"
                break;
            fi;
        done;
    done;
    if [[ ${OSTYPE} == "linux-gnu" ]] || [[ ${OSTYPE} == "linux-gnueabihf" ]]; then
        DETECTED_SERVICES+=("linux")
        HMENU+=("linux" "on")
    else 
        log_info "NOT A LINUX"
    fi;

    if [[ ${SILENT} == "false" ]]; then
        #we put whiptail results in an array, notice the dark magic fd redirection
        DETECTED_SERVICES=($(whiptail --separate-output --noitem --ok-button Continue --title "Services to monitor" --checklist "Detected services, uncheck to ignore. Ignored services won't be monitored." 18 70 10 ${HMENU[@]} 3>&1 1>&2 2>&3))
        if [ $? -eq 1 ]; then
            log_err "user bailed out at services selection"
            exit 1;
        fi;
        log_dbg "Detected services (interactive) : ${DETECTED_SERVICES[@]}"
    else
        log_dbg "Detected services (unattended) : ${DETECTED_SERVICES[@]}"
    fi;
}

declare -A log_input_tags
log_input_tags[apache2]='type: apache2'
log_input_tags[nginx]='type: nginx'
log_input_tags[sshd]='type: syslog'
log_input_tags[rsyslog]='type: syslog'
log_input_tags[telnet]='type: telnet'
log_input_tags[mysql]='type: mysql'
log_input_tags[smb]='type: smb'
log_input_tags[linux]="type: syslog"

declare -A log_locations
log_locations[apache2]='/var/log/apache2/*.log,/var/log/*httpd*.log,/var/log/httpd/*log'
log_locations[nginx]='/var/log/nginx/*.log,/usr/local/openresty/nginx/logs/*.log'
log_locations[sshd]='/var/log/auth.log,/var/log/sshd.log,/var/log/secure'
log_locations[rsyslog]='/var/log/syslog'
log_locations[telnet]='/var/log/telnetd*.log'
log_locations[mysql]='/var/log/mysql/error.log'
log_locations[smb]='/var/log/samba*.log'
log_locations[linux]='/var/log/syslog,/var/log/kern.log,/var/log/messages'

#$1 is service name, such those in SUPPORTED_SERVICES
find_logs_for() {
    ret=""
    x=${1}
    #we have trailing and starting quotes because of whiptail
    SVC="${x%\"}"
    SVC="${SVC#\"}"
    DETECTED_LOGFILES=()
    HMENU=()
    #log_info "Searching logs for ${SVC} : ${log_locations[${SVC}]}"

    #split the line into an array with ',' separator
    OIFS=${IFS}
    IFS=',' read -r -a a <<< "${log_locations[${SVC}]},"
    IFS=${OIFS}
    #readarray -td, a <<<"${log_locations[${SVC}]},"; unset 'a[-1]';
    for poss_path in "${a[@]}"; do
        #Split /var/log/nginx/*.log into '/var/log/nginx' and '*.log' so we can use find
	    path=${poss_path%/*}
	    fname=${poss_path##*/}
	    candidates=`find "${path}" -type f -mtime -5 -ctime -5 -name "$fname"`
	    #We have some candidates, add them
	    for final_file in ${candidates} ; do
	        log_dbg "Found logs file for '${SVC}': ${final_file}"
	        DETECTED_LOGFILES+=(${final_file})
            HMENU+=(${final_file} "on")
	    done;
    done;

    if [[ ${SILENT} == "false" ]]; then
        DETECTED_LOGFILES=($(whiptail --separate-output  --noitem --ok-button Continue --title "Log files to process for ${SVC}" --checklist "Detected logfiles for ${SVC}, uncheck to ignore" 18 70 10 ${HMENU[@]} 3>&1 1>&2 2>&3))
        if [ $? -eq 1 ]; then
            log_err "user bailed out at log file selection"
            exit 1;
        fi;
    fi
}

in_array() {
    str=$1
    shift
    array=("$@")
    for element in "${array[@]}"; do
        if [[ ${str} == crowdsecurity/${element} ]]; then
            return 0
        fi
    done
    return 1
}

install_collection() {
    HMENU=()
    readarray -t AVAILABLE_COLLECTION < <(${CSCLI_BIN_INSTALLED} collections list -o raw -a)
    COLLECTION_TO_INSTALL=()
    for collect_info in "${AVAILABLE_COLLECTION[@]:1}"; do
        collection="$(echo ${collect_info} | cut -d "," -f1)"
        description="$(echo ${collect_info} | cut -d "," -f4)"
        in_array $collection "${DETECTED_SERVICES[@]}"
        if [[ $? == 0 ]]; then
            HMENU+=("${collection}" "${description}" "ON")
            #in case we're not in interactive mode, assume defaults
            COLLECTION_TO_INSTALL+=(${collection})
        else
            if [[ ${collection} == "linux" ]]; then
                HMENU+=("${collection}" "${description}" "ON")
                #in case we're not in interactive mode, assume defaults
                COLLECTION_TO_INSTALL+=(${collection})
            else
                HMENU+=("${collection}" "${description}" "OFF")
            fi
        fi
    done

    if [[ ${SILENT} == "false" ]]; then
        COLLECTION_TO_INSTALL=($(whiptail --separate-output --ok-button Continue --title "Crowdsec collections" --checklist "Available collections in crowdsec, try to pick one that fits your profile. Collections contains parsers and scenarios to protect your system." 20 120 10 "${HMENU[@]}" 3>&1 1>&2 2>&3))
        if [ $? -eq 1 ]; then
            log_err "user bailed out at collection selection"
            exit 1;
        fi;
    fi;

    for collection in "${COLLECTION_TO_INSTALL[@]}"; do
        log_info "Installing collection '${collection}'"
        ${CSCLI_BIN_INSTALLED} collections install "${collection}" > /dev/null 2>&1 || log_err "fail to install collection ${collection}"
    done

    ${CSCLI_BIN_INSTALLED} parsers install "crowdsecurity/whitelists" > /dev/null 2>&1 || log_err "fail to install collection crowdsec/whitelists"
    if [[ ${SILENT} == "false" ]]; then
        whiptail --msgbox "Out of safety, I installed a parser called 'crowdsecurity/whitelists'. This one will prevent private IP addresses from being banned, feel free to remove it any time." 20 50
    fi

    if [[ ${SILENT} == "false" ]]; then
        whiptail --msgbox "CrowdSec alone will not block any IP address. If you want to block them, you must use a bouncer. You can find them on https://hub.crowdsec.net/browse/#bouncers" 20 50
    fi
}

#$1 is the service name, $... is the list of candidate logs (from find_logs_for)
genyamllog() {
    local service="${1}"
    shift
    local files=("${@}")
    
    echo "#Generated acquisition file - wizard.sh (service: ${service}) / files : ${files[@]}" >> ${TMP_ACQUIS_FILE}
    
    echo "filenames:"  >> ${TMP_ACQUIS_FILE}
    for fd in ${files[@]}; do
	echo "  - ${fd}"  >> ${TMP_ACQUIS_FILE}
    done
    echo "labels:"  >> ${TMP_ACQUIS_FILE}
    echo "  "${log_input_tags[${service}]}  >> ${TMP_ACQUIS_FILE}
    echo "---"  >> ${TMP_ACQUIS_FILE}
    log_dbg "tmp acquisition file generated to: ${TMP_ACQUIS_FILE}"
}

genyamljournal() {
    local service="${1}"
    shift
    
    echo "#Generated acquisition file - wizard.sh (service: ${service}) / files : ${files[@]}" >> ${TMP_ACQUIS_FILE}
    
    echo "journalctl_filter:"  >> ${TMP_ACQUIS_FILE}
    echo " - _SYSTEMD_UNIT="${service}".service"  >> ${TMP_ACQUIS_FILE}
    echo "labels:"  >> ${TMP_ACQUIS_FILE}
    echo "  "${log_input_tags[${service}]}  >> ${TMP_ACQUIS_FILE}
    echo "---"  >> ${TMP_ACQUIS_FILE}
    log_dbg "tmp acquisition file generated to: ${TMP_ACQUIS_FILE}"
}

genacquisition() {
    log_dbg "Found following services : "${DETECTED_SERVICES[@]}
    for PSVG in ${DETECTED_SERVICES[@]} ; do
        find_logs_for ${PSVG}
        if [[ ${#DETECTED_LOGFILES[@]} -gt 0 ]] ; then
            log_info "service '${PSVG}': ${DETECTED_LOGFILES[*]}"
            genyamllog ${PSVG} ${DETECTED_LOGFILES[@]}
	elif [[ ${PSVG} != "linux" ]] ; then
	    log_info "using journald for '${PSVG}'"
	    genyamljournal ${PSVG}
        fi;
    done 
}

detect_cs_install () {
    if [[ -f "$CROWDSEC_BIN_INSTALLED" ]]; then
        log_warn "Crowdsec is already installed !"
        echo ""
        echo "We recommand to upgrade : sudo ./wizard.sh --upgrade "
        echo "If you want to install it anyway, please use '--force'."
        echo ""
        echo "Run : sudo ./wizard.sh -i --force"
        if [[ ${FORCE_MODE} == "false" ]]; then
            exit 1
        fi
    fi
}

check_cs_version () {
    CURRENT_CS_VERSION=$(crowdsec -version 2>&1 | grep version | grep -Eio 'v[0-9]+.[0-9]+.[0-9]+' | cut -c 2-)
    NEW_CS_VERSION=$($CROWDSEC_BIN -version 2>&1 | grep version | grep -Eio 'v[0-9]+.[0-9]+.[0-9]+' | cut -c 2-)
    CURRENT_MAJOR_VERSION=$(echo $CURRENT_CS_VERSION | cut -d'.' -f1)
    CURRENT_MINOR_VERSION=$(echo $CURRENT_CS_VERSION | cut -d'.' -f2)
    CURRENT_PATCH_VERSION=$(echo $CURRENT_CS_VERSION | cut -d'.' -f3)
    NEW_MAJOR_VERSION=$(echo $NEW_CS_VERSION | cut -d'.' -f1)
    NEW_MINOR_VERSION=$(echo $NEW_CS_VERSION | cut -d'.' -f2)
    NEW_PATCH_VERSION=$(echo $NEW_CS_VERSION | cut -d'.' -f3)

    if [[ $NEW_MAJOR_VERSION -gt $CURRENT_MAJOR_VERSION ]]; then
        if [[ ${FORCE_MODE} == "false" ]]; then
            log_warn "new version ($NEW_CS_VERSION) is a major, you should follow documentation to upgrade !"
            echo ""
            exit 1
        fi
    elif [[ $NEW_MINOR_VERSION -gt $CURRENT_MINOR_VERSION ]] ; then
        log_warn "new version ($NEW_CS_VERSION) is a minor upgrade !"
        if [[ $ACTION != "upgrade" ]] ; then 
            if [[ ${FORCE_MODE} == "false" ]]; then
                echo ""
                echo "We recommand to upgrade with : sudo ./wizard.sh --upgrade "
                echo "If you want to $ACTION anyway, please use '--force'."
                echo ""
                echo "Run : sudo ./wizard.sh --$ACTION --force"
                exit 1
            fi
        fi
    elif [[ $NEW_PATCH_VERSION -gt $CURRENT_PATCH_VERSION ]] ; then
        log_warn "new version ($NEW_CS_VERSION) is a patch !"
        if [[ $ACTION != "binupgrade" ]] ; then 
            if [[ ${FORCE_MODE} == "false" ]]; then
                echo ""
                echo "We recommand to upgrade binaries only : sudo ./wizard.sh --binupgrade "
                echo "If you want to $ACTION anyway, please use '--force'."
                echo ""
                echo "Run : sudo ./wizard.sh --$ACTION --force"
                exit 1
            fi
        fi
    elif [[ $NEW_MINOR_VERSION -eq $CURRENT_MINOR_VERSION ]]; then
        log_warn "new version ($NEW_CS_VERSION) is same as current version ($CURRENT_CS_VERSION) !"
        if [[ ${FORCE_MODE} == "false" ]]; then
            echo ""
            echo "We recommand to $ACTION only if it's an higher version. "
            echo "If it's an RC version (vX.X.X-rc) you can upgrade it using '--force'."
            echo ""
            echo "Run : sudo ./wizard.sh --$ACTION --force"
            exit 1
        fi
    fi
}

#install crowdsec and cscli
install_crowdsec() {
    mkdir -p "${CROWDSEC_DATA_DIR}"
    mkdir -p "${CROWDSEC_CONSOLE_DIR}"

    (cd config && find patterns -type f -exec install -Dm 644 "{}" "${CROWDSEC_CONFIG_PATH}/{}" \; && cd ../) || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/scenarios" || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/postoverflows" || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/collections" || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/patterns" || exit

    #tmp
    mkdir -p /tmp/data
    mkdir -p /etc/crowdsec/hub/
    install -v -m 600 -D "./config/${CLIENT_SECRETS}" "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 600 -D "./config/${LAPI_SECRETS}" "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit

    ## end tmp

    install -v -m 644 -D ./config/config.yaml "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 644 -D ./config/dev.yaml "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 644 -D ./config/user.yaml "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 644 -D ./config/acquis.yaml "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 644 -D ./config/profiles.yaml "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 644 -D ./config/simulation.yaml "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 644 -D ./config/"${CONSOLE_FILE}" "${CROWDSEC_CONFIG_PATH}" 1> /dev/null || exit
    install -v -m 644 -D ./config/labels.yaml "${CROWDSEC_CONSOLE_DIR}" 1> /dev/null || exit

    DATA=${CROWDSEC_DATA_DIR} CFG=${CROWDSEC_CONFIG_PATH} envsubst '$CFG $DATA' < ./config/user.yaml > ${CROWDSEC_CONFIG_PATH}"/user.yaml" || log_fatal "unable to generate user configuration file"
    if [[ ${DOCKER_MODE} == "false" ]]; then
        CFG=${CROWDSEC_CONFIG_PATH} BIN=${CROWDSEC_BIN_INSTALLED} envsubst '$CFG $BIN' < ./config/crowdsec.service > "${SYSTEMD_PATH_FILE}" || log_fatal "unable to crowdsec systemd file"
    fi
    install_bins

    if [[ ${DOCKER_MODE} == "false" ]]; then
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

    if [[ ! -f "$CROWDSEC_BIN" ]]; then
        log_err "Crowdsec binary '$CROWDSEC_BIN' not found. Please build it with 'make build'" && exit
    fi
    if [[ ! -f "$CSCLI_BIN" ]]; then
        log_err "Cscli binary '$CSCLI_BIN' not found. Please build it with 'make build'" && exit
    fi

    log_info "Backing up existing configuration"
    ${CSCLI_BIN_INSTALLED} config backup ${BACKUP_DIR}
    log_info "Saving default database content if exist"
    if [[ -f "/var/lib/crowdsec/data/crowdsec.db" ]]; then
        cp /var/lib/crowdsec/data/crowdsec.db ${BACKUP_DIR}/crowdsec.db
    fi
    log_info "Cleanup existing crowdsec configuration"
    uninstall_crowdsec
    log_info "Installing crowdsec"
    install_crowdsec
    log_info "Restoring configuration"
    ${CSCLI_BIN_INSTALLED} hub update
    ${CSCLI_BIN_INSTALLED} config restore ${BACKUP_DIR}
    log_info "Restoring saved database if exist"
    if [[ -f "${BACKUP_DIR}/crowdsec.db" ]]; then
        cp ${BACKUP_DIR}/crowdsec.db /var/lib/crowdsec/data/crowdsec.db
    fi
    log_info "Finished, restarting"
    systemctl restart crowdsec || log_fatal "Failed to restart crowdsec"
}

install_bins() {
    log_dbg "Installing crowdsec binaries"
    install -v -m 755 -D "${CROWDSEC_BIN}" "${CROWDSEC_BIN_INSTALLED}" 1> /dev/null || exit
    install -v -m 755 -D "${CSCLI_BIN}" "${CSCLI_BIN_INSTALLED}" 1> /dev/null || exit
    which systemctl && systemctl is-active --quiet crowdsec
    if [ $? -eq 0 ]; then
        systemctl stop crowdsec 
    fi
    install_plugins
    symlink_bins
}

symlink_bins() {
    if grep -q "${BIN_INSTALL_PATH}" <<< $PATH; then
        log_dbg "${BIN_INSTALL_PATH} found in PATH"
    else
        ln -s "${CSCLI_BIN_INSTALLED}" /usr/bin/cscli
        ln -s "${CROWDSEC_BIN_INSTALLED}" /usr/bin/crowdsec
    fi
}

delete_bins() {
    log_info "Removing crowdsec binaries"
    rm -f ${CROWDSEC_BIN_INSTALLED}
    rm -f ${CSCLI_BIN_INSTALLED}   
}

delete_plugins() {
    rm -rf ${CROWDSEC_PLUGIN_DIR}
}

install_plugins(){
    mkdir -p ${CROWDSEC_PLUGIN_DIR}
    mkdir -p /etc/crowdsec/notifications

    cp ${SLACK_PLUGIN_BINARY} ${CROWDSEC_PLUGIN_DIR}
    cp ${SPLUNK_PLUGIN_BINARY} ${CROWDSEC_PLUGIN_DIR}
    cp ${HTTP_PLUGIN_BINARY} ${CROWDSEC_PLUGIN_DIR}
    cp ${EMAIL_PLUGIN_BINARY} ${CROWDSEC_PLUGIN_DIR}

    if [[ ${DOCKER_MODE} == "false" ]]; then
        cp -n ${SLACK_PLUGIN_CONFIG} /etc/crowdsec/notifications/
        cp -n ${SPLUNK_PLUGIN_CONFIG} /etc/crowdsec/notifications/
        cp -n ${HTTP_PLUGIN_CONFIG} /etc/crowdsec/notifications/
        cp -n ${EMAIL_PLUGIN_CONFIG} /etc/crowdsec/notifications/
    fi
}

check_running_bouncers() {
    #when uninstalling, check if user still has bouncers
    BOUNCERS_COUNT=$(${CSCLI_BIN} bouncers list -o=json | jq '. | length')
    if [[ ${BOUNCERS_COUNT} -gt 0 ]] ; then
        if [[ ${FORCE_MODE} == "false" ]]; then
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
    systemctl stop crowdsec.service 1>/dev/null
    systemctl disable -q crowdsec.service 1>/dev/null
    ${CSCLI_BIN} dashboard remove -f -y >/dev/null
    delete_bins

    # tmp
    rm -rf /tmp/data/
    ## end tmp

    find /etc/crowdsec -maxdepth 1 -mindepth 1 | grep -v "bouncer" | xargs rm -rf || echo ""
    rm -f ${CROWDSEC_LOG_FILE} || echo ""
    rm -f ${LAPI_LOG_FILE} || echo ""
    rm -f ${CROWDSEC_DB_PATH} || echo ""
    rm -rf ${CROWDSEC_LIB_DIR} || echo ""
    rm -rf ${CROWDSEC_USR_DIR} || echo ""
    rm -f ${SYSTEMD_PATH_FILE} || echo ""
    log_info "crowdsec successfully uninstalled"
}


function show_link {
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

    if [ "$1" == "install" ] || [ "$1" == "configure" ] || [ "$1" == "detect" ]; then
        if [ "${SILENT}" == "false" ]; then
            which whiptail > /dev/null
            if [ $? -ne 0 ]; then
                log_fatal "whiptail binary is needed to use the wizard in interactive mode, exiting ..."
            fi
        fi
        which envsubst > /dev/null
        if [ $? -ne 0 ]; then
            log_fatal "envsubst binary is needed to use do a full install with the wizard, exiting ..."
        fi
    fi

    if [[ "$1" == "binupgrade" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run the wizard as root or with sudo"
            exit 1
        fi
        check_cs_version
        update_bins
        return
    fi

    if [[ "$1" == "upgrade" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run the wizard as root or with sudo"
            exit 1
        fi
        check_cs_version
        update_full
        return
    fi

    if [[ "$1" == "configure" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run the wizard as root or with sudo"
            exit 1
        fi
        detect_services
        ${CSCLI_BIN_INSTALLED} hub update
        install_collection
        genacquisition
        mv "${TMP_ACQUIS_FILE}" "${ACQUIS_TARGET}"

        return
    fi

    if [[ "$1" == "noop" ]];
    then
        return
    fi
   
    if [[ "$1" == "uninstall" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run the wizard as root or with sudo"
            exit 1
        fi
        check_running_bouncers
        uninstall_crowdsec
        return
    fi

    if [[ "$1" == "bininstall" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run the wizard as root or with sudo"
            exit 1
        fi
        log_info "checking existing crowdsec install"
        detect_cs_install
        log_info "installing crowdsec"
        install_crowdsec

        show_link
        return
    fi

    if [[ "$1" == "install" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run the wizard as root or with sudo"
            exit 1
        fi
        log_info "checking if crowdsec is installed"
        detect_cs_install
        ## Do make build before installing (as non--root) in order to have the binary and then install crowdsec as root
        log_info "installing crowdsec"
        install_crowdsec
        log_dbg "configuring ${CSCLI_BIN_INSTALLED}"
        ${CSCLI_BIN_INSTALLED} hub update > /dev/null 2>&1 || (log_err "fail to update crowdsec hub. exiting" && exit 1)

        # detect running services
        detect_services
        if ! [ ${#DETECTED_SERVICES[@]} -gt 0 ] ; then 
            log_err "No detected or selected services, stopping."
            exit 1
        fi;

        # Generate acquisition file and move it to the right folder
        genacquisition
        mv "${TMP_ACQUIS_FILE}" "${ACQUIS_TARGET}"
        log_info "acquisition file path: ${ACQUIS_TARGET}"
        # Install collections according to detected services
        log_dbg "Installing needed collections ..."
        install_collection

        # install patterns/ folder
        log_dbg "Installing patterns"
        mkdir -p "${PATTERNS_PATH}"
        cp "./${PATTERNS_FOLDER}/"* "${PATTERNS_PATH}/"


        # api register
        ${CSCLI_BIN_INSTALLED} machines add --force "$(cat /etc/machine-id)" -a -f "${CROWDSEC_CONFIG_PATH}/${CLIENT_SECRETS}" || log_fatal "unable to add machine to the local API"
        log_dbg "Crowdsec LAPI registered" 
        
        ${CSCLI_BIN_INSTALLED} capi register || log_fatal "unable to register to the Central API"
        log_dbg "Crowdsec CAPI registered" 
       
        systemctl enable -q crowdsec >/dev/null || log_fatal "unable to enable crowdsec"
        systemctl start crowdsec >/dev/null || log_fatal "unable to start crowdsec"
        log_info "enabling and starting crowdsec daemon"
        show_link
        return
    fi

    if [[ "$1" == "detect" ]];
    then
        rm -f "${TMP_ACQUIS_FILE}"
        detect_services
        if [[ ${DETECTED_SERVICES} == "" ]] ; then 
            log_err "No detected or selected services, stopping."
            exit
        fi;
        log_info "Found ${#DETECTED_SERVICES[@]} supported services running:"
        genacquisition
        cat "${TMP_ACQUIS_FILE}"
        rm "${TMP_ACQUIS_FILE}"
        return
    fi

}

usage() {
      echo "Usage:"
      echo "    ./wizard.sh -h                               Display this help message."
      echo "    ./wizard.sh -d|--detect                      Detect running services and associated logs file"
      echo "    ./wizard.sh -i|--install                     Assisted installation of crowdsec/cscli and collections"
      echo "    ./wizard.sh --bininstall                     Install binaries and empty config, no wizard."
      echo "    ./wizard.sh --uninstall                      Uninstall crowdsec/cscli"
      echo "    ./wizard.sh --binupgrade                     Upgrade crowdsec/cscli binaries"
      echo "    ./wizard.sh --upgrade                        Perform a full upgrade and try to migrate configs"
      echo "    ./wizard.sh --unattended                     Install in unattended mode, no question will be asked and defaults will be followed"
      echo "    ./wizard.sh --docker-mode                    Will install crowdsec without systemd and generate random machine-id"
      echo "    ./wizard.sh -n|--noop                        Do nothing"

      exit 0  
}

if [[ $# -eq 0 ]]; then
usage
fi

while [[ $# -gt 0 ]]
do
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
    -d|--detect)
        ACTION="detect"
        shift # past argument
        ;;
    -n|--noop)
        ACTION="noop"
        shift # past argument
        ;;
    --unattended)
        SILENT="true"
        ACTION="install"
        shift
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

main ${ACTION}
