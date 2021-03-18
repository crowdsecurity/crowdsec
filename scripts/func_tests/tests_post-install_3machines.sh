#! /usr/bin/env bash
# -*- coding: utf-8 -*-

source tests_base.sh

## machines

${CSCLI} machines list -ojson | ${JQ} '. | length == 1' || fail "expected exactly one machine"

# add a new machine
${CSCLI} machines add -a -f ./test_machine.yaml CiTestMachine -ojson || fail "expected exactly one machine"
${CSCLI} machines list -ojson | ${JQ} '. | length == 2' || fail "expected exactly one machine"
${CSCLI} machines delete CiTestMachine -ojson || fail "expected exactly one machine"
${CSCLI} machines list -ojson | ${JQ} '. | length == 1' || fail "expected exactly one machine"

#try register/validate
${CSCLI} lapi register  --machine CiTestMachineRegister -f new_machine.yaml
#the newly added machine isn't validated yet
${CSCLI} machines list -ojson | ${JQ} '.[1].isValidated == null' || fail "machine shouldn't be validated"
${CSCLI} machines validate CiTestMachineRegister  || fail "failed to validate machine"
${CSCLI} machines list -ojson | ${JQ} '.[1].isValidated == true' || fail "machine should be validated"

