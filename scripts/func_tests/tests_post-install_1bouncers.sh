#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh


## bouncers

# we should have 0 bouncers
${CSCLI} bouncers list -ojson  | ${JQ} '. | length == 0' || fail "expected 0 bouncers"

# we can add one bouncer - should we save token for later ?
${CSCLI} bouncers add ciTestBouncer || fail "failed to add bouncer"

# but we can't add it twice - we would get a fatal error
${CSCLI} bouncers add ciTestBouncer -ojson  2>&1 | ${JQ} '.level == "fatal"' || fail "didn't receive the expected error"

# we should have 1 bouncer
${CSCLI} bouncers list -ojson  | ${JQ} '. | length == 1' || fail "expected 1 bouncers"

# delete the bouncer :)
${CSCLI} bouncers delete ciTestBouncer || fail "failed to delete bouncer"

# we should have 0 bouncers
${CSCLI} bouncers list -ojson  | ${JQ} '. | length == 0' || fail "expected 0 bouncers"


