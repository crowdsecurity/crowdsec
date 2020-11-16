ARG ARCH=amd64
ARG OS=linux
ARG GOVERSION=1.14

FROM golang:${GOVERSION}-alpine

WORKDIR /go/src/crowdsec
COPY . .

RUN apk update && apk add git jq gcc libc-dev make bash gettext
RUN export BUILD_VERSION="$(git describe --tags `git rev-list --tags --max-count=1`)"
RUN make release

WORKDIR /go/src/crowdsec
RUN /bin/bash wizard.sh --docker-mode
RUN sed -ri 's/^(\s*)(daemonize\s*:\s*true\s*$)/\1daemonize: false/' /etc/crowdsec/config.yaml
RUN sed -ri 's/^(\s*)(log_media\s*:\s*file\s*$)/\1log_media: stdout/' /etc/crowdsec/config.yaml
RUN cscli hub update
RUN cscli collections install crowdsecurity/linux

RUN rm -rf /go/src/crowdsec
RUN apk del git jq gcc libc-dev make bash gettext

#ENTRYPOINT ["crowdsec", "-c", "/etc/crowdsec/config.yaml", "-t"]
CMD crowdsec -c /etc/crowdsec/config.yaml



