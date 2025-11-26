#!/usr/bin/env sh
set -eu

umask 027

CROWDSEC_VERSION="latest"
ARCHIVE_PATH=""
BASE_DIR="${HOME}/.local/share/crowdsec"
BASE_DIR_SET=false
INSTALL_DIR="${BASE_DIR}/runtime"
INSTALL_DIR_SET=false
CONFIG_DIR="${HOME}/.config/crowdsec"
CONFIG_DIR_SET=false
DATA_DIR="${BASE_DIR}/data"
DATA_DIR_SET=false
LOG_DIR="${BASE_DIR}/log"
LOG_DIR_SET=false
BIN_DIR="${HOME}/.local/bin"
BIN_DIR_SET=false
RUN_MODE="auto" # Initialize to 'auto'
FORCE=false
AUTO=false
SKIP_CAPI=false
COLLECTIONS="crowdsecurity/linux"
TMP_DIR=""
ARCHIVE_FILE=""
SOURCE_DIR=""
INSTALL_BIN_DIR=""
CONFIG_FILE=""
SYSTEMD_UNIT_NAME="crowdsec-user.service"
LOCAL_API_URL="http://127.0.0.1:8080"
ACTUAL_RUN_MODE="none"

usage() {
    cat <<EOF
Usage: ${0##*/} [options]

Options:
  --version <tag>          CrowdSec release tag (default: latest)
  --archive <path>         Use a pre-downloaded crowdsec-release.tgz archive
  --base-dir <dir>         Base directory for data/logs/runtime (default: $BASE_DIR)
  --install-dir <dir>      Directory where binaries are staged (default: ${INSTALL_DIR})
  --config-dir <dir>       Configuration directory (default: $CONFIG_DIR)
  --data-dir <dir>         Data directory (default: $DATA_DIR)
  --log-dir <dir>          Log directory (default: $LOG_DIR)
  --bin-dir <dir>          Wrapper/bin directory to expose crowdsec & cscli (default: $BIN_DIR)
  --collections <list>     Comma-separated collections to install (default: $COLLECTIONS)
                           Use --collections none to skip automatic installs.
  --run-mode <auto|systemd|nohup|none>
                           How to start the service (default: auto)
  --skip-capi              Do not register the instance to the Central API
  --force                  Overwrite/backup any existing installation
  -h, --help               Show this help text
EOF
}

log() {
    printf '[%s] %s\n' "$1" "$2" >&2
}

info() {
    log INFO "$1"
}

warn() {
    log WARN "$1"
}

fail() {
    log ERROR "$1"
    exit 1
}

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trim() {
    trimmed_string=$(echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    echo "$trimmed_string"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
        --force)
            FORCE=true
            shift
            ;;
        --auto)
            AUTO=true
            shift
            ;;
        --version)
            [ "$#" -lt 2 ] && fail "--version expects an argument"
            CROWDSEC_VERSION="$2"
            shift 2
            ;;
        --archive)
            [ "$#" -lt 2 ] && fail "--archive expects a file path"
            ARCHIVE_PATH="$2"
            shift 2
            ;;
        --base-dir)
            [ "$#" -lt 2 ] && fail "--base-dir expects a directory"
            BASE_DIR="$2"
            BASE_DIR_SET=true
            shift 2
            ;;
        --install-dir)
            [ "$#" -lt 2 ] && fail "--install-dir expects a directory"
            INSTALL_DIR="$2"
            INSTALL_DIR_SET=true
            shift 2
            ;;
        --config-dir)
            [ "$#" -lt 2 ] && fail "--config-dir expects a directory"
            CONFIG_DIR="$2"
            CONFIG_DIR_SET=true
            shift 2
            ;;
        --data-dir)
            [ "$#" -lt 2 ] && fail "--data-dir expects a directory"
            DATA_DIR="$2"
            DATA_DIR_SET=true
            shift 2
            ;;
        --log-dir)
            [ "$#" -lt 2 ] && fail "--log-dir expects a directory"
            LOG_DIR="$2"
            LOG_DIR_SET=true
            shift 2
            ;;
        --bin-dir)
            [ "$#" -lt 2 ] && fail "--bin-dir expects a directory"
            BIN_DIR="$2"
            BIN_DIR_SET=true
            shift 2
            ;;
        --collections)
            [ "$#" -lt 2 ] && fail "--collections expects a value"
            COLLECTIONS="$2"
            shift 2
            ;;
        --run-mode)
            [ "$#" -lt 2 ] && fail "--run-mode expects a value"
            RUN_MODE="$2"
            shift 2
            ;;
        --skip-capi)
            SKIP_CAPI=true
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            ;;
        esac
    done
}

adjust_paths() {
    if [ "$BASE_DIR_SET" = true ]; then
        if [ "$INSTALL_DIR_SET" != true ]; then
            INSTALL_DIR="${BASE_DIR}/runtime"
        fi
        if [ "$DATA_DIR_SET" != true ]; then
            DATA_DIR="${BASE_DIR}/data"
        fi
        if [ "$LOG_DIR_SET" != true ]; then
            LOG_DIR="${BASE_DIR}/log"
        fi
        if [ "$CONFIG_DIR_SET" != true ]; then
            CONFIG_DIR="${BASE_DIR}/config"
        fi
    fi

    CONFIG_FILE="${CONFIG_DIR}/config.yaml"
    INSTALL_BIN_DIR="${INSTALL_DIR}/bin"
}

main() {
    parse_args "$@"
    adjust_paths

    if [ "
" -eq 0 ]; then
        warn "This script targets unprivileged installs; running as root is not recommended"
    fi

    case "$RUN_MODE" in
    auto | systemd | nohup | none) ;;
    *) fail "--run-mode must be one of auto, systemd, nohup, none" ;;
    esac

    # Remaining installation logic follows...
}

trap cleanup EXIT
main "$@"
