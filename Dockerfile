# vim: set ft=dockerfile:
ARG BUILD_ENV=full
ARG GOVERSION=1.19

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/crowdsec

COPY . .

# wizard.sh requires GNU coreutils
RUN apk add --no-cache git gcc libc-dev make bash gettext binutils-gold coreutils && \
    SYSTEM="docker" make clean release && \
    cd crowdsec-v* && \
    ./wizard.sh --docker-mode && \
    cd - && \
    cscli hub update && \
    cscli collections install crowdsecurity/linux && \
    cscli parsers install crowdsecurity/whitelists

FROM alpine:latest as build-slim

RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community tzdata yq bash && \
    mkdir -p /staging/etc/crowdsec && \
    mkdir -p /staging/var/lib/crowdsec && \
    mkdir -p /var/lib/crowdsec/data \
    yq -n '.url="http://0.0.0.0:8080"' | install -m 0600 /dev/stdin /staging/etc/crowdsec/local_api_credentials.yaml

COPY --from=build /etc/crowdsec /staging/etc/crowdsec
COPY --from=build /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=build /usr/local/bin/cscli /usr/local/bin/cscli
COPY --from=build /go/src/crowdsec/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/docker/config.yaml /staging/etc/crowdsec/config.yaml

# NOTE: setting default values here will overwrite the ones set in config.yaml
#       every time the container is started. We set the default in docker/config.yaml
#       and document them in docker/README.md, but keep the variables empty here.

ENV CONFIG_FILE=/etc/crowdsec/config.yaml
ENV LOCAL_API_URL=
ENV CUSTOM_HOSTNAME=localhost
ENV PLUGIN_DIR=
ENV DISABLE_AGENT=false
ENV DISABLE_LOCAL_API=false
ENV DISABLE_ONLINE_API=false
ENV DSN=
ENV TYPE=
ENV TEST_MODE=false
ENV USE_WAL=

# register to app.crowdsec.net

ENV ENROLL_INSTANCE_NAME=
ENV ENROLL_KEY=
ENV ENROLL_TAGS=

# log verbosity

ENV LEVEL_TRACE=
ENV LEVEL_DEBUG=
ENV LEVEL_INFO=

# TLS setup ----------------------------------- #

ENV AGENT_USERNAME=
ENV AGENT_PASSWORD=

# TLS setup ----------------------------------- #

ENV USE_TLS=false

ENV LAPI_CACERT_FILE=
ENV LAPI_CERT_FILE=
ENV LAPI_KEY_FILE=

ENV CLIENT_CACERT_FILE=
ENV CLIENT_CERT_FILE=
ENV CLIENT_KEY_FILE=

# comma-separated list of allowed OU values for TLS bouncer certificates
ENV BOUNCERS_ALLOWED_OU=

# comma-separated list of allowed OU values for TLS agent certificates
ENV AGENTS_ALLOWED_OU=

# Install the following hub items --------------#

ENV COLLECTIONS=
ENV PARSERS=
ENV SCENARIOS=
ENV POSTOVERFLOWS=

# Uninstall the following hub items ------------#

ENV DISABLE_COLLECTIONS=
ENV DISABLE_PARSERS=
ENV DISABLE_SCENARIOS=
ENV DISABLE_POSTOVERFLOWS=

ENV METRICS_PORT=

ENTRYPOINT /bin/bash docker_start.sh

FROM build-slim as build-plugins

# Due to the wizard using cp -n, we have to copy the config files directly from the source as -n does not exist in busybox cp
# The files are here for reference, as users will need to mount a new version to be actually able to use notifications
COPY --from=build /go/src/crowdsec/plugins/notifications/email/email.yaml /staging/etc/crowdsec/notifications/email.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/http/http.yaml /staging/etc/crowdsec/notifications/http.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/slack/slack.yaml /staging/etc/crowdsec/notifications/slack.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/splunk/splunk.yaml /staging/etc/crowdsec/notifications/splunk.yaml
COPY --from=build /usr/local/lib/crowdsec/plugins /usr/local/lib/crowdsec/plugins

FROM build-slim as build-geoip

COPY --from=build /var/lib/crowdsec /staging/var/lib/crowdsec

FROM build-plugins as build-full

COPY --from=build /var/lib/crowdsec /staging/var/lib/crowdsec

FROM build-${BUILD_ENV}
