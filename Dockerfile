ARG GOVERSION=1.14

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/crowdsec

RUN apk add --no-cache git jq gcc libc-dev make bash gettext

COPY . .

RUN SYSTEM="docker" make release
RUN /bin/bash wizard.sh --docker-mode
RUN cscli hub update && cscli collections install crowdsecurity/linux

FROM alpine:latest
RUN wget https://github.com/mikefarah/yq/releases/download/v4.4.1/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq && apk add tzdata
COPY --from=build /etc/crowdsec /etc/crowdsec
COPY --from=build /var/lib/crowdsec /var/lib/crowdsec
COPY --from=build /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=build /usr/local/bin/cscli /usr/local/bin/cscli
COPY --from=build /go/src/crowdsec/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/docker/config.yaml /etc/crowdsec/config.yaml

ENTRYPOINT /bin/sh docker_start.sh