#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh

## collections

${CSCLI_BIN} collections list || fail "failed to list collections"

BASE_COLLECTION_COUNT=2

# we expect 1 collections : linux 
${CSCLI_BIN} collections list -ojson | ${JQ} ".collections | length == ${BASE_COLLECTION_COUNT}" || fail "(first) expected exactly ${BASE_COLLECTION_COUNT} collection"

# install an extra collection
${CSCLI} collections install crowdsecurity/mysql || fail "failed to install collection"

BASE_COLLECTION_COUNT=$((BASE_COLLECTION_COUNT+1))

# we should now have 2 collections :)
${CSCLI_BIN} collections list -ojson | ${JQ} ".collections | length == ${BASE_COLLECTION_COUNT}" || fail "(post install) expected exactly ${BASE_COLLECTION_COUNT} collection"

# remove the collection
${CSCLI} collections remove crowdsecurity/mysql || fail "failed to remove collection"

BASE_COLLECTION_COUNT=$((BASE_COLLECTION_COUNT-1))

# we expect 1 collections : linux 
${CSCLI_BIN} collections list -ojson | ${JQ} ".collections | length == ${BASE_COLLECTION_COUNT}" || fail "(post remove) expected exactly ${BASE_COLLECTION_COUNT} collection"

