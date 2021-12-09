#! /usr/bin/env bash
# -*- coding: utf-8 -*-

# Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
OK_STR="${GREEN}OK${NC}"
FAIL_STR="${RED}FAIL${NC}"

CURRENT_FOLDER=$(pwd)

BOUNCER_VERSION="v0.0.6"
RELEASE_FOLDER=""

HUB_AVAILABLE_PARSERS="/etc/crowdsec/hub/parsers"
HUB_AVAILABLE_SCENARIOS="/etc/crowdsec/hub/scenarios"
HUB_AVAILABLE_COLLECTIONS="/etc/crowdsec/hub/collections"
HUB_AVAILABLE_PO="/etc/crowdsec/hub/postoverflows"

HUB_ENABLED_PARSERS="/etc/crowdsec/parsers"
HUB_ENABLED_SCENARIOS="/etc/crowdsec/scenarios"
HUB_ENABLED_COLLECTIONS="/etc/crowdsec/collections"
HUB_ENABLED_PO="/etc/crowdsec/postoverflows"

ACQUIS_FILE="/etc/crowdsec/acquis.yaml"
PROFILE_FILE="/etc/crowdsec/profiles.yaml"
CONFIG_FILE="/etc/crowdsec/config.yaml"
LOCAL_API_FILE="/etc/crowdsec/local_api_credentials.yaml"
ONLINE_API_FILE="/etc/crowdsec/online_api_credentials.yaml"
SIMULATION_FILE="/etc/crowdsec/simulation.yaml"
DB_FILE="/var/lib/crowdsec/data/crowdsec.db"

SYSTEMD_FILE="/etc/systemd/system/crowdsec.service"

BOUNCER_FOLDER="/etc/crowdsec/cs-firewall-bouncer"

MUST_FAIL=0

function init
{
    which git > /dev/null
    if [ $? -ne 0 ]; then
        echo "git is needed this test, exiting ..."
    fi
    if [[ -z ${RELEASE_FOLDER} ]];
    then
      cd ..
      BUILD_VERSION=${CROWDSEC_VERSION} make release
      if [ $? != 0 ]; then
        echo "Unable to make the release (make sur you have go installed), exiting"
        exit 1
      fi
      RELEASE_FOLDER="crowdsec-${CROWDSEC_VERSION}"
    fi
    cp -r ${RELEASE_FOLDER} ${CURRENT_FOLDER}
    cd ${CURRENT_FOLDER}


    echo "[*] Installing crowdsec (bininstall)"
    cd ${RELEASE_FOLDER}/
    ./wizard.sh --bininstall
    cd ${CURRENT_FOLDER}
    cscli hub update
    cscli collections install crowdsecurity/sshd
    cscli postoverflows install crowdsecurity/cdn-whitelist
    cscli machines add -a
    systemctl start crowdsec


    echo "[*] Install firewall bouncer"
    wget https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/${BOUNCER_VERSION}/cs-firewall-bouncer.tgz
    tar xzvf cs-firewall-bouncer.tgz
    cd cs-firewall-bouncer-${BOUNCER_VERSION}/
    (echo "iptables" | sudo ./install.sh) || (echo "Unable to install cs-firewall-bouncer" && exit 1)
    cd ${CURRENT_FOLDER}

    echo "[*] Tainting parser /etc/crowdsec/parsers/s01-parse/sshd-logs.yaml"
    echo "  # test taint parser" >> /etc/crowdsec/parsers/s01-parse/sshd-logs.yaml

    echo "[*] Tainting scenario /etc/crowdsec/scenarios/ssh-bf.yaml"
    echo "  # test taint scenario" >> /etc/crowdsec/scenarios/ssh-bf.yaml

    echo "[*] Tainting postoverflow /etc/crowdsec/postoverflows/s01-whitelist/cdn-whitelist.yaml"
    echo "  # test taint postoverflow" >> /etc/crowdsec/postoverflows/s01-whitelist/cdn-whitelist.yaml

    echo "[*] Tainting new systemd configuration file"
    echo "  # test taint systemd file" >> ${RELEASE_FOLDER}/config/crowdsec.service

    echo "[*] Tainting profile file"
    echo "  # test taint profile file" >> ${PROFILE_FILE}

    echo "[*] Tainting acquis file"
    echo "  # test taint acquis file" >> ${ACQUIS_FILE}

    echo "[*] Tainting local_api_creds file"
    echo "  # test taint local_api_creds file" >> ${LOCAL_API_FILE}

    echo "[*] Tainting online_api_creds file"
    echo "  # test taint online_api_creds file" >> ${ONLINE_API_FILE}

    echo "[*] Tainting config file"
    echo "  # test taint config file" >> ${CONFIG_FILE}

    echo "[*] Tainting simulation file"
    echo "  # test taint simulation file" >> ${SIMULATION_FILE}

    echo "[*] Adding a decision"
    cscli decisions add -i 1.2.3.4


    find ${HUB_ENABLED_PARSERS} -type l -exec md5sum "{}" + >> parsers_enabled.md5
    find ${HUB_ENABLED_SCENARIOS} -type l -exec md5sum "{}" + >> scenarios_enabled.md5
    find ${HUB_ENABLED_COLLECTIONS} -type l -exec md5sum "{}" + >> collections_enabled.md5
    find ${HUB_ENABLED_PO} -type l -exec md5sum "{}" + >> po_enabled.md5

    md5sum ${ACQUIS_FILE} >> acquis.md5
    md5sum ${PROFILE_FILE} >> profile.md5
    md5sum ${LOCAL_API_FILE} >> local_api_creds.md5
    md5sum ${ONLINE_API_FILE} >> online_api_creds.md5
    md5sum ${CONFIG_FILE} >> config.md5
    md5sum ${SIMULATION_FILE} >> simulation.md5
    md5sum ${DB_FILE} >> db.md5
    md5sum ${SYSTEMD_FILE} >> systemd.md5

    echo "[*] Setup done"
    echo "[*] Lauching the upgrade"
    cd ${RELEASE_FOLDER}/
    ./wizard.sh --upgrade --force
    cd ${CURRENT_FOLDER}
    echo "[*] Upgrade done, checking results"
}

function down
{
  cd ${RELEASE_FOLDER}/
  ./wizard.sh --uninstall
  cd ${CURRENT_FOLDER}
  rm -rf crowdsec-v*
  rm -rf cs-firewall-bouncer-*
  rm -f crowdsec-release.tgz
  rm -f cs-firewall-bouncer.tgz
  rm -- *.md5
}

function assert_equal
{
  echo ""
  if [ "$1" = "$2" ]; then
    echo -e "Status - ${GREEN}OK${NC}"
  else
    echo -e "Status - ${RED}FAIL${NC}"
    echo "Details:"
    echo ""
    diff  <(echo "$1" ) <(echo "$2")
    MUST_FAIL=1
  fi
  echo "-----------------------------------------------------------------------"
}

function assert_not_equal
{
  echo ""
  if [ "$1" != "$2" ]; then
    echo -e "Status - ${GREEN}OK${NC}"
  else
    echo -e "Status - ${RED}FAIL${NC}"
    echo "Details:"
    echo ""
    diff  <(echo "$1" ) <(echo "$2")
    MUST_FAIL=1
  fi
  echo "-----------------------------------------------------------------------"
}

function assert_folder_exists
{
  echo ""
  if [ -d "${BOUNCER_FOLDER}" ]
  then
    echo -e "Status - ${GREEN}OK${NC}"
  else
    echo -e "Status - ${RED}FAIL${NC}"
    echo "Folder '$1' doesn't exist, but should"
    MUST_FAIL=1
  fi
  echo "-----------------------------------------------------------------------"
}

function test_enabled_parsers
{
  echo $FUNCNAME
  new=$(find ${HUB_ENABLED_PARSERS} -type f -exec md5sum "{}" +)
  old=$(cat parsers_enabled.md5)
  assert_equal "$new" "$old"

}

function test_enabled_scenarios
{
  echo $FUNCNAME
  new=$(find ${HUB_ENABLED_SCENARIOS} -type f -exec md5sum "{}" +)
  old=$(cat scenarios_enabled.md5)
  assert_equal "$new" "$old"

}

function test_enabled_collections
{
  echo $FUNCNAME
  new=$(find ${HUB_ENABLED_COLLECTIONS} -type f -exec md5sum "{}" +)
  old=$(cat collections_enabled.md5)
  assert_equal "$new" "$old"

}

function test_enabled_po
{
  echo $FUNCNAME
  new=$(find ${HUB_ENABLED_PO} -type f -exec md5sum "{}" +)
  old=$(cat po_enabled.md5)
  assert_equal "$new" "$old"
}

function test_config_file
{
  echo $FUNCNAME
  new=$(find ${CONFIG_FILE} -type f -exec md5sum "{}" +)
  old=$(cat config.md5)
  assert_equal "$new" "$old"
}

function test_acquis_file
{
  echo $FUNCNAME
  new=$(find ${ACQUIS_FILE} -type f -exec md5sum "{}" +)
  old=$(cat acquis.md5)
  assert_equal "$new" "$old"
}

function test_local_api_creds_file
{
  echo $FUNCNAME
  new=$(find ${LOCAL_API_FILE} -type f -exec md5sum "{}" +)
  old=$(cat local_api_creds.md5)
  assert_equal "$new" "$old"
}


function test_online_api_creds_file
{
  echo $FUNCNAME
  new=$(find ${ONLINE_API_FILE} -type f -exec md5sum "{}" +)
  old=$(cat online_api_creds.md5)
  assert_equal "$new" "$old"
}

function test_profile_file
{
  echo $FUNCNAME
  new=$(find ${PROFILE_FILE} -type f -exec md5sum "{}" +)
  old=$(cat profile.md5)
  assert_equal "$new" "$old"
}

function test_db_file
{
  echo $FUNCNAME
  new=$(find ${DB_FILE} -type f -exec md5sum "{}" +)
  old=$(cat db.md5)
  assert_equal "$new" "$old"
}

function test_simulation_file
{
  echo $FUNCNAME
  new=$(find ${SIMULATION_FILE} -type f -exec md5sum "{}" +)
  old=$(cat simulation.md5)
  assert_equal "$new" "$old"
}

function test_systemd_file
{
  echo $FUNCNAME
  new=$(find ${SYSTEMD_FILE} -type f -exec md5sum "{}" +)
  old=$(cat systemd.md5)
  assert_not_equal "$new" "$old"
}

function test_bouncer_dir
{
  echo $FUNCNAME
  assert_folder_exists ${BOUNCER_FOLDER}
}

function start_test
{
  echo ""
  echo "-----------------------------------------------------------------------"
  test_enabled_parsers
  test_enabled_scenarios
  test_enabled_collections
  test_enabled_po
  test_config_file
  test_acquis_file
  test_online_api_creds_file
  test_local_api_creds_file
  test_profile_file
  test_simulation_file
  test_db_file
  test_systemd_file
  test_bouncer_dir
}


usage() {
      echo "Usage:"
      echo ""
      echo "    ./test_wizard_upgrade.sh -h                                   Display this help message."
      echo "    ./test_wizard_upgrade.sh                                      Run all the testsuite. Go must be available to make the release"
      echo "    ./test_wizard_upgrade.sh --release <path_to_release_folder>   If go is not installed, please provide a path to the crowdsec-vX.Y.Z release folder"
      echo ""
      exit 0  
}

while [[ $# -gt 0 ]]
do
    key="${1}"
    case ${key} in
    --version|-v)
        CROWDSEC_VERSION="${2}"
        shift #past argument
        shift
        ;;   
    --release|-r)
        RELEASE_FOLDER="${2}"
        shift #past argument
        shift
        ;;   
    -h|--help)
        usage
        exit 0
        ;;
    *)    # unknown option
        echo "Unknown argument ${key}."
        usage
        exit 1
        ;;
    esac
done


init
start_test
down
if [ ${MUST_FAIL} -eq 1 ]
then
  exit 1
fi