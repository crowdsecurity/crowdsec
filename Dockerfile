ARG GOVERSION=1.14

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/crowdsec
COPY . .

RUN apk update && apk add git jq gcc libc-dev make bash gettext
RUN BUILD_VERSION="$(git describe --tags `git rev-list --tags --max-count=1`)" make release
RUN /bin/bash wizard.sh --docker-mode
RUN cscli hub update && cscli collections install crowdsecurity/linux

FROM alpine:latest
COPY --from=build /etc/crowdsec /etc/crowdsec
COPY --from=build /var/lib/crowdsec /var/lib/crowdsec
COPY --from=build /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=build /usr/local/bin/cscli /usr/local/bin/cscli
COPY --from=build /go/src/crowdsec/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/docker/config.yaml /etc/crowdsec/config.yaml


ENTRYPOINT /bin/sh docker_start.sh