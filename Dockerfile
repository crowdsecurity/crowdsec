ARG GOVERSION=1.16

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/crowdsec

RUN apk update && apk add --no-cache git jq gcc libc-dev make bash gettext binutils-gold

COPY . .

RUN SYSTEM="docker" make release
RUN /bin/bash wizard.sh --docker-mode
RUN cscli hub update && cscli collections install crowdsecurity/linux

FROM alpine:latest
RUN apk update --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community && apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community tzdata yq
COPY --from=build /etc/crowdsec /etc/crowdsec
COPY --from=build /var/lib/crowdsec /var/lib/crowdsec
COPY --from=build /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=build /usr/local/bin/cscli /usr/local/bin/cscli
COPY --from=build /go/src/crowdsec/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/docker/config.yaml /etc/crowdsec/config.yaml

ENTRYPOINT /bin/sh docker_start.sh