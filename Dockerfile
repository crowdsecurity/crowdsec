ARG GOVERSION=1.17

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/crowdsec

# wizard.sh requires GNU coreutils
RUN apk add --no-cache git gcc libc-dev make bash gettext binutils-gold coreutils

COPY . .

RUN SYSTEM="docker" make release
RUN cd crowdsec-v* && ./wizard.sh --docker-mode && cd -
RUN cscli hub update && cscli collections install crowdsecurity/linux && cscli parsers install crowdsecurity/whitelists
FROM alpine:latest
RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community tzdata yq jq bash && \
  mkdir -p /staging/etc/crowdsec && \
  mkdir -p /staging/var/lib/crowdsec
COPY --from=build /etc/crowdsec /staging/etc/crowdsec
COPY --from=build /var/lib/crowdsec /staging/var/lib/crowdsec
COPY --from=build /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=build /usr/local/bin/cscli /usr/local/bin/cscli
COPY --from=build /go/src/crowdsec/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/docker/config.yaml /staging/etc/crowdsec/config.yaml
#Due to the wizard using cp -n, we have to copy the config files directly from the source as -n does not exist in busybox cp
#The files are here for reference, as users will need to mount a new version to be actually able to use notifications
COPY --from=build /go/src/crowdsec/plugins/notifications/email/email.yaml /staging/etc/crowdsec/notifications/email.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/http/http.yaml /staging/etc/crowdsec/notifications/http.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/slack/slack.yaml /staging/etc/crowdsec/notifications/slack.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/splunk/splunk.yaml /staging/etc/crowdsec/notifications/splunk.yaml
COPY --from=build /usr/local/lib/crowdsec/plugins /usr/local/lib/crowdsec/plugins

ENTRYPOINT /bin/bash docker_start.sh
