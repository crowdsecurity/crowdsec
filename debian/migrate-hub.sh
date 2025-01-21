#!/usr/bin/env sh

set -eu

if [ ! -d /var/lib/crowdsec/hub/ ]; then
    echo "You don't have a hub directory to migrate."
    echo
    echo "Use this script only if you upgrade from the crowdsec package included in the debian repositories."
    exit 1
fi

# Download everything on the new hub but don't install anything yet

echo "Downloading Hub content..."

for itemtype in $(cscli hub types -o raw); do
    ALL_ITEMS=$(cscli "$itemtype" list -a -o raw | tail +2 | cut -d, -f1)
    if [ -n "${ALL_ITEMS}" ]; then
        # shellcheck disable=SC2086
        cscli "$itemtype" install \
            $ALL_ITEMS \
            --download-only -y
    fi
done

# Fix links

BASEDIR=/etc/crowdsec/
OLD_PATH=/var/lib/crowdsec/hub/
NEW_PATH=/etc/crowdsec/hub/

find "$BASEDIR" -type l 2>/dev/null | while IFS= read -r link
do
    target="$(readlink "$link")" || continue

    case "$target" in
        "$OLD_PATH"*)
            suffix="${target#"$OLD_PATH"}"
            new_target="${NEW_PATH}${suffix}"

            if [ -e "$target" ]; then
                continue
            fi

            if [ ! -e "$new_target" ]; then
                continue
            fi

            echo "Update symlink: $link"
            ln -sf "$new_target" "$link"
            ;;
        *)
            ;;
    esac
done

# upgrade tainted collections

cscli hub upgrade --force
