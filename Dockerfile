# vim: set ft=dockerfile:
FROM python:3-alpine as onnxruntimebuild

ARG ONNXRUNTIME_VERSION=1.12.1

RUN apk add --no-cache --update  \
        gcc \
        musl-dev \
        linux-headers \
        python3-dev \
        cmake \
        curl \
        tar \
        ca-certificates \
        g++ \
        git \
        lapack-dev \
        openblas-dev \
        zlib-dev \
        build-base \
        && \
        pip install --upgrade pip cython numpy pybind11 pytest wheel packaging setuptools

RUN git clone https://github.com/microsoft/onnxruntime.git --branch "v${ONNXRUNTIME_VERSION}" --recursive /onnxruntime

WORKDIR /onnxruntime

RUN apk add --no-cache \
    ninja-build \
    libexecinfo-dev \
    flatbuffers \
    libprotobuf \
    protobuf \
    protobuf-dev=3.6.1-r1 --repository=http://dl-cdn.alpinelinux.org/alpine/v3.10/main

RUN /bin/sh /onnxruntime/build.sh --config Release \
    --skip_tests \
    --cmake_extra_defines \
    onnxruntime_BUILD_UNIT_TESTS=OFF \
    CMAKE_CXX_FLAGS=-w \
    --parallel --build_shared_lib
    

FROM rust:1.70.0-slim-bullseye AS rust_build

WORKDIR /

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    make
RUN git clone https://github.com/daulet/tokenizers.git /tokenizer && \
    cd /tokenizer && \
    cargo build --release && \
    cp target/release/libtokenizers.a /tokenizer/libtokenizers.a

FROM golang:1.22.4-alpine3.20 AS build

ARG BUILD_VERSION
ARG ONNXRUNTIME_VERSION=1.12.1

WORKDIR /go/src/crowdsec

# We like to choose the release of re2 to use, and Alpine does not ship a static version anyway.
ENV RE2_VERSION=2023-03-01
ENV BUILD_VERSION=${BUILD_VERSION}

# wizard.sh requires GNU coreutils
RUN apk add --no-cache git g++ gcc libc-dev make bash gettext binutils-gold coreutils pkgconfig && \
    wget https://github.com/google/re2/archive/refs/tags/${RE2_VERSION}.tar.gz && \
    tar -xzf ${RE2_VERSION}.tar.gz && \
    cd re2-${RE2_VERSION} && \
    make install && \
    echo "githubciXXXXXXXXXXXXXXXXXXXXXXXX" > /etc/machine-id && \
    go install github.com/mikefarah/yq/v4@v4.43.1

COPY . .

COPY --from=rust_build /tokenizer/libtokenizers.a /usr/local/lib/


# INSTALL ONNXRUNTIME
# RUN cd /tmp && \
#     wget -O onnxruntime.tgz https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/onnxruntime-linux-aarch64-${ONNXRUNTIME_VERSION}.tgz && \
#     tar -C /tmp -xvf onnxruntime.tgz && \
#     mv onnxruntime-linux-aarch64-${ONNXRUNTIME_VERSION} onnxruntime && \
#     rm -rf onnxruntime.tgz && \
#     cp -R onnxruntime/lib /usr/local && \
#     cp -R onnxruntime/include /usr/local && \
#     rm -rf onnxruntime

COPY --from=onnxruntimebuild /onnxruntime/build/Linux/RelWithDebInfo/onnxruntime/lib /usr/local/lib/
COPY --from=onnxruntimebuild /onnxruntime/build/Linux/RelWithDebInfo/onnxruntime/include /usr/local/include/

RUN make clean release DOCKER_BUILD=1 BUILD_STATIC=0 CGO_CFLAGS="-D_LARGEFILE64_SOURCE -I/usr/local/include"  \
        CGO_LDFLAGS="-L/usr/local/lib -lonnxruntime -lstdc++ /usr/local/lib/libtokenizers.a -ldl -lm -L/usr/local/lib -lonnxruntime" \
        CGO_CPPFLAGS="-I/usr/local/include" \
        LIBRARY_PATH="/usr/local/lib" \
        LD_LIBRARY_PATH="/usr/local/lib" && \
    cd crowdsec-v* && \
    ./wizard.sh --docker-mode && \
    cd - >/dev/null && \
    cscli hub update && \
    ./docker/preload-hub-items && \
    cscli collections install crowdsecurity/linux && \
    cscli parsers install crowdsecurity/whitelists

    # In case we need to remove agents here..
    # cscli machines list -o json | yq '.[].machineId' | xargs -r cscli machines delete

FROM alpine:latest as slim

RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community tzdata bash rsync && \
    mkdir -p /staging/etc/crowdsec && \
    mkdir -p /staging/etc/crowdsec/acquis.d && \
    mkdir -p /staging/var/lib/crowdsec && \
    mkdir -p /var/lib/crowdsec/data

COPY --from=build /go/bin/yq /usr/local/bin/crowdsec /usr/local/bin/cscli /usr/local/bin/
COPY --from=build /etc/crowdsec /staging/etc/crowdsec
COPY --from=build /go/src/crowdsec/docker/docker_start.sh /
COPY --from=build /go/src/crowdsec/docker/config.yaml /staging/etc/crowdsec/config.yaml
COPY --from=build /var/lib/crowdsec /staging/var/lib/crowdsec
RUN yq -n '.url="http://0.0.0.0:8080"' | install -m 0600 /dev/stdin /staging/etc/crowdsec/local_api_credentials.yaml

ENTRYPOINT /bin/bash /docker_start.sh

FROM slim as full

# Due to the wizard using cp -n, we have to copy the config files directly from the source as -n does not exist in busybox cp
# The files are here for reference, as users will need to mount a new version to be actually able to use notifications
COPY --from=build \
    /go/src/crowdsec/cmd/notification-email/email.yaml \
    /go/src/crowdsec/cmd/notification-http/http.yaml \
    /go/src/crowdsec/cmd/notification-slack/slack.yaml \
    /go/src/crowdsec/cmd/notification-splunk/splunk.yaml \
    /go/src/crowdsec/cmd/notification-sentinel/sentinel.yaml \
    /staging/etc/crowdsec/notifications/

COPY --from=build /usr/local/lib/crowdsec/plugins /usr/local/lib/crowdsec/plugins
