#! /usr/bin/env bash
# -*- coding: utf-8 -*-

if pidof crowdsec; then
    fail "crowdsec shouldn't run anymore"
fi

