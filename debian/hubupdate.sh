#!/bin/sh

set -eu

test -x /usr/bin/cscli || exit 0

/usr/bin/cscli --error hub update >/dev/null

upgraded="$(/usr/bin/cscli --error hub upgrade)"
if [ -n "$upgraded" ]; then
  systemctl reload crowdsec.service
fi
