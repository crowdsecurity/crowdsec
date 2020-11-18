#!/usr/bin/env bash

set -o pipefail
#set -x


RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SILENT="false"
DOCKER_MODE="false"

CROWDSEC_RUN_DIR="/var/run"
CROWDSEC_LIB_DIR="/var/lib/crowdsec"
CROWDSEC_USR_DIR="/usr/local/lib/crowdsec"
CROWDSEC_DATA_DIR="${CROWDSEC_LIB_DIR}/data"
CROWDSEC_PLUGIN_DIR="${CROWDSEC_USR_DIR}/plugins"
CROWDSEC_PLUGIN_BACKEND_DIR="${CROWDSEC_PLUGIN_DIR}/backend"
CROWDSEC_DB_PATH="${CROWDSEC_DATA_DIR}/crowdsec.db"
CROWDSEC_PATH="/etc/crowdsec"
CROWDSEC_CONFIG_PATH="${CROWDSEC_PATH}"
CROWDSEC_LOG_FILE="/var/log/crowdsec.log"
CROWDSEC_BACKEND_FOLDER="/etc/crowdsec/plugins/backend"
CSCLI_FOLDER="/etc/crowdsec/config/cscli"

CROWDSEC_BIN="./cmd/crowdsec/crowdsec"
CSCLI_BIN="./cmd/crowdsec-cli/cscli"


CLIENT_SECRETS="local_api_credentials.yaml"
LAPI_SECRETS="online_api_credentials.yaml"

CROWDSEC_BIN_INSTALLED="/usr/local/bin/crowdsec"
CSCLI_BIN_INSTALLED="/usr/local/bin/cscli"

ACQUIS_PATH="${CROWDSEC_CONFIG_PATH}"
TMP_ACQUIS_FILE="tmp-acquis.yaml"
ACQUIS_TARGET="${ACQUIS_PATH}/acquis.yaml"

PID_DIR="${CROWDSEC_RUN_DIR}"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec.service"

PATTERNS_FOLDER="config/patterns"
PATTERNS_PATH="${CROWDSEC_CONFIG_PATH}/patterns/"

ACTION=""

DEBUG_MODE="false"

SUPPORTED_SERVICES='apache2
nginx
sshd
mysql
telnet
smb
'

BACKUP_DIR=$(mktemp -d)
rm -rf $BACKUP_DIR


log_info() {
    msg=$1
    date=$(date +%x:%X)
    echo -e "[${date}][${BLUE}INF${NC}] crowdsec_wizard: ${msg}"
}

log_err() {
    msg=$1
    date=$(date +%x:%X)
    echo -e "[${date}][${RED}ERR${NC}] crowdsec_wizard: ${msg}" 1>&2
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
        log_info "Checking if service '${SVC}' is running (ps+systemd)"
        for SRC in "${SYSTEMD_SERVICES}" "${PSAX}" ; do
            echo ${SRC} | grep ${SVC} >/dev/null
            if [ $? -eq 0 ]; then
                DETECTED_SERVICES+=(${SVC})
                HMENU+=(${SVC} "on")
                log_info "Found '${SVC}' running"
                break;
            fi;
        done;
    done;
    if [[ ${OSTYPE} == "linux-gnu" ]]; then
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
        echo "Detected services (interactive) : ${DETECTED_SERVICES[@]}"
    else
        echo "Detected services (unattended) : ${DETECTED_SERVICES[@]}"
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
log_locations[apache2]='/var/log/apache2/*.log,/var/log/*httpd*.log'
log_locations[nginx]='/var/log/nginx/*.log'
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
	        log_info "Found logs file for '${SVC}': ${final_file}"
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
        if [[ ${str} == *${element}* ]]; then
            return 0
        fi
    done
    return 1
}

install_collection() {
    HMENU=()
    readarray -t AVAILABLE_COLLECTION < <(${CSCLI_BIN_INSTALLED} collections list -o raw -a)
    COLLECTION_TO_INSTALL=()
    for collect_info in "${AVAILABLE_COLLECTION[@]}"; do
        collection="$(echo ${collect_info} | cut -d " " -f1)"
        description="$(echo ${collect_info} | cut -d " " -f2-)"
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
        whiptail --msgbox "Out of safety, I installed a parser called 'crowdsecurity/whitelists'. This one will prevent private IP adresses from being banned, feel free to remove it any time." 20 50
    fi


    if [[ ${SILENT} == "false" ]]; then
        whiptail --msgbox "CrowdSec alone will not block any IP address. If you want to block them, you must use a bouncer. You can find them on https://hub.crowdsec.net/" 20 50
    fi

}



#$1 is the service name, $... is the list of candidate logs (from find_logs_for)
genyaml() {
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
    log_info "Acquisition file generated"
}

genacquisition() {
    log_info "Found following services : "${DETECTED_SERVICES[@]}
    for PSVG in ${DETECTED_SERVICES[@]} ; do
        find_logs_for ${PSVG}
        if [[ ${#DETECTED_LOGFILES[@]} -gt 0 ]] ; then
        	genyaml ${PSVG} ${DETECTED_LOGFILES[@]}
        fi;
    done 
}

delete_plugins(){
    rm -rf "${CROWDSEC_PLUGIN_DIR}"
    rm -rf "${CROWDSEC_BACKEND_FOLDER}"
}

install_plugins() {
    install_plugins_bin
    mkdir -p "${CROWDSEC_BACKEND_FOLDER}" || exit
    cp -r ./config/plugins/backend/* "${CROWDSEC_BACKEND_FOLDER}" || exit
}

install_plugins_bin() {
    mkdir -p "${CROWDSEC_PLUGIN_BACKEND_DIR}" || exit
}


#install crowdsec and cscli
install_crowdsec() {
    mkdir -p "${CROWDSEC_DATA_DIR}"
    (cd config && find patterns -type f -exec install -Dm 644 "{}" "${CROWDSEC_CONFIG_PATH}/{}" \; && cd ../) || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/scenarios" || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/postoverflows" || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/collections" || exit
    mkdir -p "${CROWDSEC_CONFIG_PATH}/patterns" || exit
    mkdir -p "${CSCLI_FOLDER}" || exit

    #tmp
    mkdir -p /tmp/data
    mkdir -p /etc/crowdsec/hub/
    install -v -m 600 -D "./config/${CLIENT_SECRETS}" "${CROWDSEC_CONFIG_PATH}" || exit
    install -v -m 600 -D "./config/${LAPI_SECRETS}" "${CROWDSEC_CONFIG_PATH}" || exit

    ## end tmp

    install -v -m 644 -D ./config/config.yaml "${CROWDSEC_CONFIG_PATH}" || exit
    install -v -m 644 -D ./config/prod.yaml "${CROWDSEC_CONFIG_PATH}" || exit
    install -v -m 644 -D ./config/dev.yaml "${CROWDSEC_CONFIG_PATH}" || exit
    install -v -m 644 -D ./config/acquis.yaml "${CROWDSEC_CONFIG_PATH}" || exit
    install -v -m 644 -D ./config/profiles.yaml "${CROWDSEC_CONFIG_PATH}" || exit
    install -v -m 600 -D ./config/api.yaml "${CROWDSEC_CONFIG_PATH}" || exit
    install -v -m 644 -D ./config/simulation.yaml "${CROWDSEC_CONFIG_PATH}" || exit
    mkdir -p ${PID_DIR} || exit
    PID=${PID_DIR} DATA=${CROWDSEC_DATA_DIR} CFG=${CROWDSEC_CONFIG_PATH} envsubst '$CFG $PID $DATA' < ./config/prod.yaml > ${CROWDSEC_CONFIG_PATH}"/default.yaml"   
    PID=${PID_DIR} DATA=${CROWDSEC_DATA_DIR} CFG=${CROWDSEC_CONFIG_PATH} envsubst '$CFG $PID $DATA' < ./config/user.yaml > ${CROWDSEC_CONFIG_PATH}"/user.yaml"
    if [[ ${DOCKER_MODE} == "false" ]]; then
        CFG=${CROWDSEC_CONFIG_PATH} PID=${PID_DIR} BIN=${CROWDSEC_BIN_INSTALLED} envsubst '$CFG $PID $BIN' < ./config/crowdsec.service > "${SYSTEMD_PATH_FILE}"
    fi
    install_bins
    install_plugins
    if [[ ${DOCKER_MODE} == "false" ]]; then
	    systemctl daemon-reload
    fi
}

update_bins() {
    log_info "Only upgrading binaries"
    delete_bins
    install_bins
    install_plugins_bin
    log_info "Upgrade finished"
    systemctl restart crowdsec
}


update_full() {

    if [[ ! -f "$CROWDSEC_BIN" ]]; then
        log_err "Crowdwatch binary '$CROWDSEC_BIN' not found. Please build it with 'make build'" && exit
    fi
    if [[ ! -f "$CSCLI_BIN" ]]; then
        log_err "Cwcli binary '$CSCLI_BIN' not found. Please build it with 'make build'" && exit
    fi

    log_info "Backing up existing configuration"
    ${CSCLI_BIN_INSTALLED} backup save ${BACKUP_DIR}
    log_info "Saving default database content"
    cp /var/lib/crowdsec/data/crowdsec.db ${BACKUP_DIR}/crowdsec.db
    log_info "Cleanup existing crowdsec configuration"
    uninstall_crowdsec
    log_info "Installing crowdsec"
    install_crowdsec
    log_info "Restoring configuration"
    ${CSCLI_BIN_INSTALLED} update
    ${CSCLI_BIN_INSTALLED} backup restore ${BACKUP_DIR}
    log_info "Restoring saved database"
    cp ${BACKUP_DIR}/crowdsec.db /var/lib/crowdsec/data/crowdsec.db
    log_info "Finished, restarting"
    systemctl restart crowdsec || log_err "Failed to restart crowdsec"
}

install_bins() {
    log_info "Installing crowdsec binaries"
    install -v -m 755 -D "${CROWDSEC_BIN}" "${CROWDSEC_BIN_INSTALLED}" || exit
    install -v -m 755 -D "${CSCLI_BIN}" "${CSCLI_BIN_INSTALLED}" || exit
    install_plugins_bin || exit
}

delete_bins() {
    log_info "Removing crowdsec binaries"
    rm -f ${CROWDSEC_BIN_INSTALLED}
    rm -f ${CSCLI_BIN_INSTALLED}   
}

# uninstall crowdsec and cscli
uninstall_crowdsec() {
    systemctl stop crowdsec.service
    ${CSCLI_BIN} dashboard remove -f -y
    delete_bins
    delete_plugins

    # tmp
    rm -rf /tmp/data/
    ## end tmp

    rm -rf ${CROWDSEC_PATH} || echo ""
    rm -f ${CROWDSEC_LOG_FILE} || echo ""
    rm -f ${CROWDSEC_DB_PATH} || echo ""
    rm -rf ${CROWDSEC_LIB_DIR} || echo ""
    rm -rf ${CROWDSEC_USR_DIR} || echo ""
    rm -f ${SYSTEMD_PATH_FILE} || echo ""
    log_info "crowdsec successfully uninstalled"
}


main() {
    if [[ "$1" == "backup_to_dir" ]];
    then
        backup_to_dir
        return
    fi
    
    if [[ "$1" == "restore_from_dir" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run it as root"
            exit 1
        fi
        restore_from_dir
        return
    fi

    if [[ "$1" == "binupgrade" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run it as root"
            exit 1
        fi
        update_bins
        return
    fi

    if [[ "$1" == "upgrade" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run it as root"
            exit 1
        fi
        update_full
        return
    fi

    if [[ "$1" == "uninstall" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run it as root"
            exit 1
        fi
        uninstall_crowdsec
        return
    fi


    if [[ "$1" == "bininstall" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run it as root"
            exit 1
        fi
        log_info "installing crowdsec"
        install_crowdsec
        # lapi register
        MACHINE_ID=""
        if [[ ${DOCKER_MODE} == "false" ]]; then
            ${CSCLI_BIN_INSTALLED} machines add --force "$(cat /etc/machine-id)" --password "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)" -f "${CROWDSEC_CONFIG_PATH}/${CLIENT_SECRETS}"
        fi
            
        log_info "Crowdsec LAPI registered"
        return
    fi


    if [[ "$1" == "install" ]];
    then
        if ! [ $(id -u) = 0 ]; then
            log_err "Please run it as root"
            exit 1
        fi

        ## Do make build before installing (as non--root) in order to have the binary and then install crowdsec as root
        log_info "installing crowdsec"
        install_crowdsec
        log_info "configuring  ${CSCLI_BIN_INSTALLED}"
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

        # Install collections according to detected services
        log_info "Installing needed collections ..."
        install_collection

        # install patterns/ folder
        log_info "Installing patterns"
        mkdir -p "${PATTERNS_PATH}"
        cp "./${PATTERNS_FOLDER}/"* "${PATTERNS_PATH}/"


        # api register
        ${CSCLI_BIN_INSTALLED} machines add --force "$(cat /etc/machine-id)" --password "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)" -f "${CROWDSEC_CONFIG_PATH}/${CLIENT_SECRETS}"
        log_info "Crowdsec LAPI registered"
        
        ${CSCLI_BIN_INSTALLED} capi register
        log_info "Crowdsec CAPI registered"

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
      echo "    ./wizard.sh -r|--restore                     Restore saved configurations from ${BACKUP_DIR} to ${CROWDSEC_CONFIG_PATH}"
      echo "    ./wizard.sh -b|--backup                      Backup existing configurations to ${BACKUP_DIR}"

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
    -b|--backup)
        ACTION="backup_to_dir"
        shift # past argument
        ;;
    -r|--restore)
        ACTION="restore_from_dir"
        shift # past argument
        ;;
    -d|--detect)
        ACTION="detect"
        shift # past argument
        ;;
    --unattended)
        SILENT="true"
        ACTION="install"
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
