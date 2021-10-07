#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh

CURRENT_DIR=$(pwd)

git clone https://github.com/crowdsecurity/hub.git
cd hub/
${CSCLI} hubtest run --all

cd "${CURRENT_DIR}"
