#!/usr/bin/env sh
set -eu

umask 027

DEFAULT_ROOT="${HOME}/.crowdsec"

CROWDSEC_VERSION="${CROWDSEC_INSTALL_VERSION:-latest}"
ARCHIVE_PATH="${CROWDSEC_INSTALL_ARCHIVE:-}"
ROOT_DIR="${CROWDSEC_ROOT_DIR:-$DEFAULT_ROOT}"
RUN_MODE="${CROWDSEC_RUN_MODE:-auto}"
AUTO=false
CLEANUP=false
COLLECTIONS="${CROWDSEC_COLLECTIONS:-crowdsecurity/linux}"
TMP_DIR=""
INSTALL_DIR=""
CONFIG_DIR=""
DATA_DIR=""
LOG_DIR=""
BIN_DIR=""
INSTALL_BIN_DIR=""
CONFIG_FILE=""
SYSTEMD_UNIT_NAME="${CROWDSEC_SYSTEMD_UNIT:-crowdsec-user.service}"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
SYSTEMD_UNIT_PATH=""
ACQUISITION_LOGDIR="${CROWDSEC_ACQUISITION_LOGDIR:-}"
ACQUISITION_LABEL="${CROWDSEC_ACQUISITION_LABEL:-}"
WRAPPER_CROWDSEC=""
WRAPPER_CSCLI=""
PID_FILE=""
ACQUIS_FILE=""
CSCLI_BIN=""
CROWDSEC_BIN=""
ARCHIVE_DIR=""


usage() {
    cat <<EOF
Usage: \\${0##*/} [options]

Options:
  --version <tag>          CrowdSec release tag (default: latest)
  --archive <path>         Use a pre-downloaded crowdsec-release.tgz archive
  --root-dir <dir>         Root directory for runtime/config/data/logs (default: $ROOT_DIR)
  --collections <list>     Comma-separated collections to install (default: $COLLECTIONS)
                           Use --collections none to skip automatic installs.
  --acquisition-logdir <path>
                           Directory or glob that points to the log files to follow.
  --acquisition-label <value>
                           Acquisition label (type) for the provided log files.
  --run-mode <auto|systemd|nohup|none>
                           How to start the service (default: auto)
  --auto                   Automatically register to the local API if possible.
  --cleanup                Remove an existing user installation and exit
  -h, --help               Show this help text

Environment overrides exist for every option, e.g. CROWDSEC_INSTALL_VERSION,\
 CROWDSEC_ROOT_DIR, CROWDSEC_RUN_MODE, CROWDSEC_COLLECTIONS, CROWDSEC_AUTO,\
 CROWDSEC_CLEANUP, CROWDSEC_ACQUISITION_LOGDIR, CROWDSEC_ACQUISITION_LABEL,\
 and CROWDSEC_SYSTEMD_UNIT.
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

to_lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

is_true() {
    case $(to_lower "$1") in
    1 | true | yes | y | on)
        return 0
        ;;
    esac
    return 1
}

apply_env_flags() {
    if [ -n "${CROWDSEC_AUTO-}" ]; then
        if is_true "$CROWDSEC_AUTO"; then
            AUTO=true
        else
            AUTO=false
        fi
    fi
    if [ -n "${CROWDSEC_CLEANUP-}" ]; then
        if is_true "$CROWDSEC_CLEANUP"; then
            CLEANUP=true
        else
            CLEANUP=false
        fi
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
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
        --root-dir)
            [ "$#" -lt 2 ] && fail "--root-dir expects a directory"
            ROOT_DIR="$2"
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
        --acquisition-logdir)
            [ "$#" -lt 2 ] && fail "--acquisition-logdir expects a path"
            ACQUISITION_LOGDIR="$2"
            shift 2
            ;;
        --acquisition-label)
            [ "$#" -lt 2 ] && fail "--acquisition-label expects a value"
            ACQUISITION_LABEL="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP=true
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
    case "$ROOT_DIR" in
    */)
        ROOT_DIR=${ROOT_DIR%/}
        ;;
    esac

    INSTALL_DIR="${ROOT_DIR}/runtime"
    CONFIG_DIR="${ROOT_DIR}/config"
    DATA_DIR="${ROOT_DIR}/data"
    LOG_DIR="${ROOT_DIR}/log"
    BIN_DIR="${ROOT_DIR}/bin"

    CONFIG_FILE="${CONFIG_DIR}/config.yaml"
    INSTALL_BIN_DIR="${INSTALL_DIR}/bin"
    ACQUIS_FILE="${CONFIG_DIR}/acquis.yaml"
    WRAPPER_CROWDSEC="${BIN_DIR}/crowdsec"
    WRAPPER_CSCLI="${BIN_DIR}/cscli"
    PID_FILE="${ROOT_DIR}/crowdsec-user.pid"
    SYSTEMD_UNIT_PATH="${SYSTEMD_USER_DIR}/${SYSTEMD_UNIT_NAME}"
}

prepare_tmp_dir() {
    if [ -n "$TMP_DIR" ]; then
        return
    fi
    TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t crowdsec)
}

resolve_version() {
    if [ "$CROWDSEC_VERSION" = "latest" ]; then
        require_cmd curl
        info "Fetching latest CrowdSec version"
        latest_json=$(curl -fsSL https://api.github.com/repos/crowdsecurity/crowdsec/releases/latest) || fail "Unable to get latest release information"
        CROWDSEC_VERSION=$(echo "$latest_json" | sed -n 's/^[[:space:]]*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
        [ -n "$CROWDSEC_VERSION" ] || fail "Unable to parse latest CrowdSec version"
    fi
}

obtain_archive() {
    if [ -n "$ARCHIVE_PATH" ]; then
        [ -f "$ARCHIVE_PATH" ] || fail "Archive not found: $ARCHIVE_PATH"
        info "Using archive $ARCHIVE_PATH"
        return
    fi

    resolve_version
    require_cmd curl
    prepare_tmp_dir
    ARCHIVE_PATH="${TMP_DIR}/crowdsec-release.tgz"
    DOWNLOAD_URL="https://github.com/crowdsecurity/crowdsec/releases/download/${CROWDSEC_VERSION}/crowdsec-release.tgz"
    info "Downloading CrowdSec ${CROWDSEC_VERSION}"
    curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE_PATH" || fail "Unable to download release from $DOWNLOAD_URL"
}

extract_archive() {
    require_cmd tar
    prepare_tmp_dir
    tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
    ARCHIVE_DIR=$(tar -tzf "$ARCHIVE_PATH" | head -n 1 | cut -d/ -f1)
    [ -n "$ARCHIVE_DIR" ] || fail "Unable to detect extracted directory"
    ARCHIVE_DIR="${TMP_DIR}/${ARCHIVE_DIR}"
    [ -d "$ARCHIVE_DIR" ] || fail "Extracted directory missing: $ARCHIVE_DIR"
}

remove_installation_artifacts() {
    rm -rf "$ROOT_DIR"
    rm -f "$SYSTEMD_UNIT_PATH"
}

prepare_install_dirs() {
    if [ -d "$ROOT_DIR" ] && [ "$(ls -A "$ROOT_DIR" 2>/dev/null)" ]; then
        fail "Existing installation detected under $ROOT_DIR. Run this script with --cleanup first."
    fi

    mkdir -p "$INSTALL_BIN_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$BIN_DIR" "$SYSTEMD_USER_DIR"
}

copy_release_payload() {
    CROWDSEC_SRC_BIN="${ARCHIVE_DIR}/cmd/crowdsec/crowdsec"
    CSCLI_SRC_BIN="${ARCHIVE_DIR}/cmd/crowdsec-cli/cscli"
    [ -x "$CROWDSEC_SRC_BIN" ] || fail "CrowdSec binary missing from archive"
    [ -x "$CSCLI_SRC_BIN" ] || fail "cscli binary missing from archive"

    cp "$CROWDSEC_SRC_BIN" "$INSTALL_BIN_DIR/crowdsec"
    cp "$CSCLI_SRC_BIN" "$INSTALL_BIN_DIR/cscli"
    chmod 0755 "$INSTALL_BIN_DIR/crowdsec" "$INSTALL_BIN_DIR/cscli"
    CROWDSEC_BIN="$INSTALL_BIN_DIR/crowdsec"
    CSCLI_BIN="$INSTALL_BIN_DIR/cscli"

    if [ -d "${ARCHIVE_DIR}/config" ]; then
        cp -R "${ARCHIVE_DIR}/config/." "$CONFIG_DIR"
    fi

    mkdir -p "${CONFIG_DIR}/hub" "${CONFIG_DIR}/acquis.d" "${CONFIG_DIR}/notifications" "${CONFIG_DIR}/plugins"
}

write_wrappers() {
    cat >"$WRAPPER_CROWDSEC" <<EOF
#!/usr/bin/env sh
exec "$CROWDSEC_BIN" -c "$CONFIG_FILE" "\$@"
EOF
    chmod 0755 "$WRAPPER_CROWDSEC"

    cat >"$WRAPPER_CSCLI" <<EOF
#!/usr/bin/env sh
exec "$CSCLI_BIN" -c "$CONFIG_FILE" "\$@"
EOF
    chmod 0755 "$WRAPPER_CSCLI"
}

render_config() {
    PLUGIN_USER=$(id -un 2>/dev/null || whoami)
    PLUGIN_GROUP=$(id -gn 2>/dev/null || id -un 2>/dev/null || whoami)

    cat >"$CONFIG_FILE" <<EOF
common:
  daemonize: false
  log_media: file
  log_level: info
  log_dir: ${LOG_DIR}/
  log_max_size: 20
  compress_logs: true
  log_max_files: 10
config_paths:
  config_dir: ${CONFIG_DIR}/
  data_dir: ${DATA_DIR}/
  simulation_path: ${CONFIG_DIR}/simulation.yaml
  hub_dir: ${CONFIG_DIR}/hub/
  index_path: ${CONFIG_DIR}/hub/.index.json
  notification_dir: ${CONFIG_DIR}/notifications/
  plugin_dir: ${CONFIG_DIR}/plugins/
crowdsec_service:
  acquisition_path: ${CONFIG_DIR}/acquis.yaml
  acquisition_dir: ${CONFIG_DIR}/acquis.d
  parser_routines: 1
cscli:
  output: human
  color: auto
db_config:
  log_level: info
  type: sqlite
  db_path: ${DATA_DIR}/crowdsec.db
plugin_config:
  user: ${PLUGIN_USER}
  group: ${PLUGIN_GROUP}
api:
  client:
    insecure_skip_verify: false
    credentials_path: ${CONFIG_DIR}/local_api_credentials.yaml
  server:
    log_level: info
    listen_uri: 127.0.0.1:8080
    profiles_path: ${CONFIG_DIR}/profiles.yaml
    console_path: ${CONFIG_DIR}/console.yaml
    online_client:
      credentials_path: ${CONFIG_DIR}/online_api_credentials.yaml
    trusted_ips:
      - 127.0.0.1
      - ::1
prometheus:
  enabled: true
  level: full
  listen_addr: 127.0.0.1
  listen_port: 6060
EOF
}

write_acquisitions() {
    if [ -z "$ACQUISITION_LOGDIR" ]; then
        fail "--acquisition-logdir is required"
    fi
    if [ -z "$ACQUISITION_LABEL" ]; then
        fail "--acquisition-label is required"
    fi
    if [ ! -e "$ACQUISITION_LOGDIR" ]; then
        fail "Acquisition path '$ACQUISITION_LOGDIR' was not found"
    fi

    cat >"$ACQUIS_FILE" <<EOF
filenames:
  - "$ACQUISITION_LOGDIR"
labels:
  type: "$ACQUISITION_LABEL"
EOF
}

cscli_bootstrap() {
    "$CSCLI_BIN" -c "$CONFIG_FILE" hub update >/dev/null 2>&1 || warn "cscli hub update failed"
}

install_collections() {
    if [ "$(trim "$COLLECTIONS")" = "none" ]; then
        info "Skipping collection installation (--collections none)"
        return
    fi

    IFS_ORIG=$IFS
    IFS=,
    for entry in $COLLECTIONS; do
        cleaned=$(trim "$entry")
        if [ -z "$cleaned" ]; then
            continue
        fi
        if "$CSCLI_BIN" -c "$CONFIG_FILE" collections install "$cleaned" >/dev/null 2>&1; then
            info "Installed collection $cleaned"
        else
            warn "Failed to install collection $cleaned"
        fi
    done
    IFS=$IFS_ORIG
}

maybe_register_machine() {
    if [ "$AUTO" != true ]; then
        return
    fi

    if "$CSCLI_BIN" -c "$CONFIG_FILE" machines add --auto --force >/dev/null 2>&1; then
        info "Generated local API credentials"
    else
        warn "Unable to generate local API credentials automatically"
    fi
}

systemd_available() {
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl --user --version >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

install_systemd_unit() {
    if ! systemd_available; then
        return 1
    fi

    cat >"$SYSTEMD_UNIT_PATH" <<EOF
[Unit]
Description=CrowdSec (user)
After=network.target

[Service]
Type=simple
ExecStart=${CROWDSEC_BIN} -c ${CONFIG_FILE}
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
StandardOutput=append:${LOG_DIR}/crowdsec.stdout.log
StandardError=append:${LOG_DIR}/crowdsec.stderr.log

[Install]
WantedBy=default.target
EOF
    chmod 0644 "$SYSTEMD_UNIT_PATH"
    return 0
}

ensure_linger_enabled() {
    if ! command -v loginctl >/dev/null 2>&1; then
        return 0
    fi

    linger_state=$(loginctl show-user "$(id -un)" -p Linger 2>/dev/null | sed 's/^Linger=//')
    if [ "$linger_state" = "yes" ]; then
        return 0
    fi

    if loginctl enable-linger "$(id -un)" >/dev/null 2>&1; then
        info "Enabled systemd user lingering for $(id -un)"
        return 0
    fi

    warn "Failed to enable systemd user lingering; the service may stop after logout"
    return 1
}

start_systemd_unit() {
    ensure_linger_enabled
    systemctl --user daemon-reload >/dev/null 2>&1 || return 1
    systemctl --user enable --now "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || return 1
    info "Started CrowdSec using systemd --user"
    return 0
}

start_nohup() {
    require_cmd nohup
    STDOUT_LOG="${LOG_DIR}/crowdsec-nohup.log"
    nohup "$CROWDSEC_BIN" -c "$CONFIG_FILE" >>"$STDOUT_LOG" 2>&1 &
    echo $! >"$PID_FILE"
    info "Started CrowdSec with nohup (PID $(cat "$PID_FILE"))"
}

stop_systemd_unit_service() {
    if ! systemd_available; then
        return
    fi
    systemctl --user stop "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || :
    systemctl --user disable "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || :
}

stop_nohup_service() {
    if [ ! -f "$PID_FILE" ]; then
        return
    fi
    pid_value=$(cat "$PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid_value" ]; then
        if kill -0 "$pid_value" >/dev/null 2>&1; then
            kill "$pid_value" >/dev/null 2>&1 || :
        fi
    fi
    rm -f "$PID_FILE"
}

cleanup_installation() {
    stop_systemd_unit_service
    stop_nohup_service
    remove_installation_artifacts
    info "Removed CrowdSec user installation under $ROOT_DIR"
}

setup_service() {
    case "$RUN_MODE" in
    auto)
        if install_systemd_unit && start_systemd_unit; then
            return
        fi
        warn "Falling back to nohup mode"
        start_nohup
        ;;
    systemd)
        install_systemd_unit || fail "systemd --user is not available"
        start_systemd_unit || fail "Failed to manage systemd --user service"
        ;;
    nohup)
        start_nohup
        ;;
    none)
        info "Skipping service start (--run-mode none)"
        ;;
    *)
        fail "--run-mode must be one of auto, systemd, nohup, none"
        ;;
    esac
}

main() {
    apply_env_flags
    parse_args "$@"
    adjust_paths

    if [ "$(id -u)" -eq 0 ]; then
        warn "This script targets unprivileged installs; running as root is discouraged"
    fi

    if [ "$CLEANUP" = true ]; then
        cleanup_installation
        info "Cleanup complete"
        exit 0
    fi

    case "$RUN_MODE" in
    auto | systemd | nohup | none) ;;
    *) fail "--run-mode must be one of auto, systemd, nohup, none" ;;
    esac

    obtain_archive
    extract_archive
    prepare_install_dirs
    copy_release_payload
    render_config
    write_acquisitions
    write_wrappers
    cscli_bootstrap
    install_collections
    maybe_register_machine
    setup_service

    info "Installation complete"
    info "Enroll to CrowdSec's Console later with: ${WRAPPER_CSCLI} console enroll <ENROLLMENT_KEY>"
}

trap cleanup EXIT
main "$@"
