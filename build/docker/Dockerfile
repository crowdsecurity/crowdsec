FROM docker.io/golang:1.25-alpine3.21 AS build

ARG BUILD_VERSION

WORKDIR /go/src/crowdsec

# We like to choose the release of re2 to use, and Alpine does not ship a static version anyway.
ENV RE2_VERSION=2023-03-01
ENV BUILD_VERSION=${BUILD_VERSION}

# wizard.sh requires GNU coreutils
RUN apk add --no-cache git g++ gcc libc-dev make bash gettext binutils-gold coreutils pkgconfig && \
    wget -q https://github.com/google/re2/archive/refs/tags/${RE2_VERSION}.tar.gz && \
    tar -xzf ${RE2_VERSION}.tar.gz && \
    cd re2-${RE2_VERSION} && \
    make install && \
    echo "githubciXXXXXXXXXXXXXXXXXXXXXXXX" > /etc/machine-id && \
    go install github.com/mikefarah/yq/v4@v4.50.1

COPY . .

RUN make clean release DOCKER_BUILD=1 BUILD_STATIC=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" && \
    cd crowdsec-v* && \
    ./wizard.sh --docker-mode && \
    cd - >/dev/null && \
    cscli hub update --with-content && \
    cscli collections install crowdsecurity/linux && \
    cscli parsers install crowdsecurity/whitelists && \
    echo '{"source": "file", "filename": "/does/not/exist", "labels": {"type": "syslog"}}' > /etc/crowdsec/acquis.yaml

    # we create a useless acquis.yaml, which will be overridden by a mounted volume
    # in most cases, but is still required for the container to start during tests

    # In case we need to remove agents here..
    # cscli machines list -o json | yq '.[].machineId' | xargs -r cscli machines delete

FROM docker.io/alpine:3.21 AS slim

RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community tzdata bash rsync && \
    mkdir -p /staging/etc/crowdsec && \
    mkdir -p /staging/etc/crowdsec/acquis.d && \
    mkdir -p /staging/var/lib/crowdsec && \
    mkdir -p /var/lib/crowdsec/data

COPY --from=build /go/bin/yq /usr/local/bin/crowdsec /usr/local/bin/cscli /usr/local/bin/
COPY --from=build /etc/crowdsec /staging/etc/crowdsec
COPY --from=build /go/src/crowdsec/build/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/build/docker/config.yaml /staging/etc/crowdsec/config.yaml
COPY --from=build /var/lib/crowdsec /staging/var/lib/crowdsec
RUN yq -n '.url="http://0.0.0.0:8080"' | install -m 0600 /dev/stdin /staging/etc/crowdsec/local_api_credentials.yaml

ENTRYPOINT ["/bin/bash", "/docker_start.sh"]

FROM slim AS full

COPY --from=build /usr/local/lib/crowdsec/plugins /usr/local/lib/crowdsec/plugins
