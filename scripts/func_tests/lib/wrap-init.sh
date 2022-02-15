#!/bin/sh

# set -eu

wrap_journalctl() {
    action="$1"
    shift
    case $action in
    start|status|stop|reload|restart|daemon-reload)
        sudo systemctl -q --no-pager "$action" "$@"
        ;;
    *)
        echo "Unkown INIT action: $action"
        exit 1
        ;;
    esac
}


# Under freebsd...
# Usage: /usr/local/etc/rc.d/crowdsec [fast|force|one|quiet](start|stop|restart|rcvar|enable|disable|delete|enabled|describe|extracommands|configtest|reload|status|poll)

wrap_rcd() {
    action=$1
    shift
    case $action in
    start|status|stop|reload|restart)
        sudo service "$@" "$action"
        ;;
    "daemon-reload")
        echo "Daemon reload not supported" >&2
        ;;
    *)
        echo "Unkown INIT action: $action" >&2
        exit 1
        ;;
    esac
}

detect_init() {
    INIT=$(ps -o comm 1 | tail -1)
    if [ "$INIT" = "systemd" ]; then
        echo wrap_journalctl
    else
        echo wrap_rcd
    fi
}

#shellcheck disable=SC2034
SYSTEMCTL=$(detect_init)

