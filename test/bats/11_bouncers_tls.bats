#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load

    tmpdir="${BATS_FILE_TMPDIR}"
    export tmpdir

    CFDIR="${BATS_TEST_DIRNAME}/testdata/cfssl"
    export CFDIR

    #gen the CA
    cfssl gencert --initca "${CFDIR}/ca.json" 2>/dev/null | cfssljson --bare "${tmpdir}/ca"
    #gen an intermediate
    cfssl gencert --initca "${CFDIR}/intermediate.json" 2>/dev/null | cfssljson --bare "${tmpdir}/inter"
    cfssl sign -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" -config "${CFDIR}/profiles.json" -profile intermediate_ca "${tmpdir}/inter.csr" 2>/dev/null | cfssljson --bare "${tmpdir}/inter"
    #gen server cert for crowdsec with the intermediate
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=server "${CFDIR}/server.json" 2>/dev/null | cfssljson --bare "${tmpdir}/server"
    #gen client cert for the bouncer
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/bouncer.json" 2>/dev/null | cfssljson --bare "${tmpdir}/bouncer"
    #gen client cert for the bouncer with an invalid OU
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/bouncer_invalid.json" 2>/dev/null | cfssljson --bare "${tmpdir}/bouncer_bad_ou"
    #gen client cert for the bouncer directly signed by the CA, it should be refused by crowdsec as uses the intermediate
    cfssl gencert -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/bouncer.json" 2>/dev/null | cfssljson --bare "${tmpdir}/bouncer_invalid"

    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/bouncer.json" 2>/dev/null | cfssljson --bare "${tmpdir}/bouncer_revoked"
    serial="$(openssl x509 -noout -serial -in "${tmpdir}/bouncer_revoked.pem" | cut -d '=' -f2)"
    echo "ibase=16; ${serial}" | bc >"${tmpdir}/serials.txt"
    cfssl gencrl "${tmpdir}/serials.txt" "${tmpdir}/ca.pem" "${tmpdir}/ca-key.pem" | base64 -d | openssl crl -inform DER -out "${tmpdir}/crl.pem"

    cat "${tmpdir}/ca.pem" "${tmpdir}/inter.pem" > "${tmpdir}/bundle.pem"

    config_set '
        .api.server.tls.cert_file=strenv(tmpdir) + "/server.pem" |
        .api.server.tls.key_file=strenv(tmpdir) + "/server-key.pem" |
        .api.server.tls.ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .api.server.tls.crl_path=strenv(tmpdir) + "/crl.pem" | 
        .api.server.tls.bouncers_allowed_ou=["bouncer-ou"]
    '

    config_disable_agent
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "there are 0 bouncers" {
    rune -0 cscli bouncers list -o json
    assert_output "[]"
}

@test "simulate one bouncer request with a valid cert" {
    rune -0 curl -s --cert "${tmpdir}/bouncer.pem" --key "${tmpdir}/bouncer-key.pem" --cacert "${tmpdir}/bundle.pem" https://localhost:8080/v1/decisions\?ip=42.42.42.42
    assert_output "null"
    rune -0 cscli bouncers list -o json
    rune -0 jq '. | length' <(output)
    assert_output '1'
    rune -0 cscli bouncers list -o json
    rune -0 jq -r '.[] | .name' <(output)
    assert_output "localhost@127.0.0.1"
    rune cscli bouncers delete localhost@127.0.0.1
}

@test "simulate one bouncer request with an invalid cert" {
    rune curl -s --cert "${tmpdir}/bouncer_invalid.pem" --key "${tmpdir}/bouncer_invalid-key.pem" --cacert "${tmpdir}/ca-key.pem" https://localhost:8080/v1/decisions\?ip=42.42.42.42
    rune -0 cscli bouncers list -o json
    assert_output "[]"
}

@test "simulate one bouncer request with an invalid OU" {
    rune curl -s --cert "${tmpdir}/bouncer_bad_ou.pem" --key "${tmpdir}/bouncer_bad_ou-key.pem" --cacert "${tmpdir}/bundle.pem" https://localhost:8080/v1/decisions\?ip=42.42.42.42
    rune -0 cscli bouncers list -o json
    assert_output "[]"
}

@test "simulate one bouncer request with a revoked certificate" {
    rune -0 curl -i -s --cert "${tmpdir}/bouncer_revoked.pem" --key "${tmpdir}/bouncer_revoked-key.pem" --cacert "${tmpdir}/bundle.pem" https://localhost:8080/v1/decisions\?ip=42.42.42.42
    assert_output --partial "access forbidden"
    rune -0 cscli bouncers list -o json
    assert_output "[]"
}
