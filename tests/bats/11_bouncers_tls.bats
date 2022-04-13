#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

config_disable_agent() {
    yq 'del(.crowdsec_service)' -i "${CONFIG_YAML}"
}

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    tmpdir=$(mktemp -d)
    export tmpdir
    #gen the CA
    cfssl gencert --initca ./cfssl/ca.json 2>/dev/null | cfssljson --bare "${tmpdir}/ca"
    #gen an intermediate
    cfssl gencert --initca ./cfssl/intermediate.json 2>/dev/null | cfssljson --bare "${tmpdir}/inter"
    cfssl sign -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" -config ./cfssl/profiles.json -profile intermediate_ca "${tmpdir}/inter.csr" 2>/dev/null | cfssljson --bare "${tmpdir}/inter"
    #gen server cert for crowdsec with the intermediate 
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config ./cfssl/profiles.json -profile=server ./cfssl/server.json 2>/dev/null | cfssljson --bare "${tmpdir}/server"
    #gen client cert for the bouncer
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/bouncer.json 2>/dev/null | cfssljson --bare "${tmpdir}/bouncer"
    #gen client cert for the bouncer directly signed by the CA, it should be refused by crowdsec as uses the intermediate
    cfssl gencert -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/bouncer_invalid.json 2>/dev/null | cfssljson --bare "${tmpdir}/bouncer_invalid" 
    
    yq '
        .api.server.tls.cert_file=strenv(tmpdir) + "/server.pem" |
        .api.server.tls.key_file=strenv(tmpdir) + "/server-key.pem" |
        .api.server.tls.ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .api.server.tls.bouncers_allowed_ou=["bouncer-ou"]
    ' -i "${CONFIG_YAML}"
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

@test "$FILE there are 0 bouncers" {
    run -0 cscli bouncers list -o json
    assert_output "[]"
}

@test "$FILE simulate one bouncer request with a valid cert" {
    run -0 curl -s --cert "${tmpdir}/bouncer.pem" --key "${tmpdir}/bouncer-key.pem" --cacert "${tmpdir}/inter.pem" https://localhost:8080/v1/decisions\?ip=42.42.42.42
    assert_output  "null"
    run -0 cscli bouncers list -o json
    run -0 jq '. | length' <(output)
    assert_output '1'
    run -0 cscli bouncers list -o json
    run -0 jq -r '.[] | .name' <(output)
    assert_output "localhost@127.0.0.1"
    run cscli bouncers delete localhost@127.0.0.1
}

@test "$FILE simulate one bouncer request with an invalid cert" {
    run curl -s --cert "${tmpdir}/bouncer_invalid.pem" --key "${tmpdir}/bouncer_invalid-key.pem" --cacert "${tmpdir}/inter.pem" https://localhost:8080/v1/decisions\?ip=42.42.42.42
    run -0 cscli bouncers list -o json
    assert_output "[]"
}