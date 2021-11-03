ARG GOVERSION=1.16

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/crowdsec

# wizard.sh requires GNU coreutils
RUN apk update && apk add --no-cache git jq gcc libc-dev make bash gettext binutils-gold coreutils

COPY . .

RUN SYSTEM="docker" make release
RUN cd crowdsec-v* && ./wizard.sh --docker-mode && cd -
RUN cscli hub update && cscli collections install crowdsecurity/linux && cscli parsers install crowdsecurity/whitelists
FROM alpine:latest
RUN apk update --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community && apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community tzdata yq
COPY --from=build /etc/crowdsec /etc/crowdsec
COPY --from=build /var/lib/crowdsec /var/lib/crowdsec
COPY --from=build /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=build /usr/local/bin/cscli /usr/local/bin/cscli
COPY --from=build /go/src/crowdsec/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/docker/config.yaml /etc/crowdsec/config.yaml
#Due to the wizard using cp -n, we have to copy the config files directly from the source as -n does not exist in busybox cp
#The files are here for reference, as users will need to mount a new version to be actually able to use notifications
COPY --from=build /go/src/crowdsec/plugins/notifications/http/http.yaml /etc/crowdsec/notifications/http.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/slack/slack.yaml /etc/crowdsec/notifications/slack.yaml
COPY --from=build /go/src/crowdsec/plugins/notifications/splunk/splunk.yaml /etc/crowdsec/notifications/splunk.yaml
COPY --from=build /usr/local/lib/crowdsec/plugins /usr/local/lib/crowdsec/plugins

ENTRYPOINT /bin/sh docker_start.sh