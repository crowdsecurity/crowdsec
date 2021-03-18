#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh

pidof crowdsec && fail "crowdsec shouldn't run anymore" || true

