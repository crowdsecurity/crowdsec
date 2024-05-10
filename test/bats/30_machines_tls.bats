#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load

    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    export CONFIG_DIR

    tmpdir="$BATS_FILE_TMPDIR"
    export tmpdir

    CFDIR="${BATS_TEST_DIRNAME}/testdata/cfssl"
    export CFDIR

    # Generate the CA
    cfssl gencert --initca "${CFDIR}/ca.json" 2>/dev/null | cfssljson --bare "${tmpdir}/ca"

    # Generate an intermediate
    cfssl gencert --initca "${CFDIR}/intermediate.json" 2>/dev/null | cfssljson --bare "${tmpdir}/inter"
    cfssl sign -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" -config "${CFDIR}/profiles.json" -profile intermediate_ca "${tmpdir}/inter.csr" 2>/dev/null | cfssljson --bare "${tmpdir}/inter"

    # Generate server cert for crowdsec with the intermediate
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=server "${CFDIR}/server.json" 2>/dev/null | cfssljson --bare "${tmpdir}/server"

    # Generate client cert for the agent
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent.json" 2>/dev/null | cfssljson --bare "${tmpdir}/agent"

    # Genearte client cert for the agent with an invalid OU
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent_invalid.json" 2>/dev/null | cfssljson --bare "${tmpdir}/agent_bad_ou"

    # Generate client cert for the bouncer directly signed by the CA, it should be refused by crowdsec as uses the intermediate
    cfssl gencert -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent.json" 2>/dev/null | cfssljson --bare "${tmpdir}/agent_invalid"

    # Generate revoked client cert
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent.json" 2>/dev/null | cfssljson --bare "${tmpdir}/agent_revoked"
    serial="$(openssl x509 -noout -serial -in "${tmpdir}/agent_revoked.pem" | cut -d '=' -f2)"
    echo "ibase=16; ${serial}" | bc >"${tmpdir}/serials.txt"
    cfssl gencrl "${tmpdir}/serials.txt" "${tmpdir}/ca.pem" "${tmpdir}/ca-key.pem" | base64 -d | openssl crl -inform DER -out "${tmpdir}/crl.pem"

    cat "${tmpdir}/ca.pem" "${tmpdir}/inter.pem" > "${tmpdir}/bundle.pem"

    config_set '
        .api.server.tls.cert_file=strenv(tmpdir) + "/server.pem" |
        .api.server.tls.key_file=strenv(tmpdir) + "/server-key.pem" |
        .api.server.tls.ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .api.server.tls.crl_path=strenv(tmpdir) + "/crl.pem" | 
        .api.server.tls.agents_allowed_ou=["agent-ou"]
    '

    # remove all machines

    for machine in $(cscli machines list -o json | jq -r '.[].machineId'); do
        cscli machines delete "${machine}" >/dev/null 2>&1
    done

    config_disable_agent
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    config_set '
        .api.server.tls.cert_file=strenv(tmpdir) + "/server.pem" |
        .api.server.tls.key_file=strenv(tmpdir) + "/server-key.pem" |
        .api.server.tls.ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .api.server.tls.crl_path=strenv(tmpdir) + "/crl.pem" | 
        .api.server.tls.agents_allowed_ou=["agent-ou"]
    '
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "missing key_file" {
    config_set '.api.server.tls.key_file=""'

    rune -0 wait-for \
        --err "missing TLS key file" \
        "$CROWDSEC"
}

@test "missing cert_file" {
    config_set '.api.server.tls.cert_file=""'

    rune -0 wait-for \
        --err "missing TLS cert file" \
        "$CROWDSEC"
}

@test "invalid OU for agent" {
    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        .ca_cert_path=strenv(tmpdir) + "/bundle.pem" |
        .key_path=strenv(tmpdir) + "/agent_bad_ou-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent_bad_ou.pem" |
        .url="https://127.0.0.1:8080"
    '

    config_set "${CONFIG_DIR}/local_api_credentials.yaml" 'del(.login,.password)'
    ./instance-crowdsec start
    rune -0 cscli machines list -o json
    assert_output '[]'
}

@test "we have exactly one machine registered with TLS" {
    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        .ca_cert_path=strenv(tmpdir) + "/bundle.pem" |
        .key_path=strenv(tmpdir) + "/agent-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent.pem" |
        .url="https://127.0.0.1:8080"
    '

    config_set "${CONFIG_DIR}/local_api_credentials.yaml" 'del(.login,.password)'
    ./instance-crowdsec start
    rune -0 cscli lapi status
    rune -0 cscli machines list -o json
    rune -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated, .[0].ipAddress, .[0].auth_type]' <(output)

    assert_output '[1,"localhost@127.0.0.1",true,"127.0.0.1","tls"]'
    rune -0 cscli machines delete localhost@127.0.0.1
}

@test "a machine can still connect with a unix socket, no TLS" {
    sock=$(config_get '.api.server.listen_socket')
    export sock

    # an agent is a machine too
    config_disable_agent
    ./instance-crowdsec start

    rune -0 cscli machines add with-socket --auto --force
    rune -0 cscli lapi status

    rune -0 cscli machines list -o json
    rune -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated, .[0].ipAddress, .[0].auth_type]' <(output)
    assert_output '[1,"with-socket",true,"127.0.0.1","password"]'

    # TLS cannot be used with a unix socket

    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        .ca_cert_path=strenv(tmpdir) + "/bundle.pem"
    '

    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: cannot use TLS with a unix socket"

    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        del(.ca_cert_path) |
        .key_path=strenv(tmpdir) + "/agent-key.pem"
    '

    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: cannot use TLS with a unix socket"

    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        del(.key_path) |
        .cert_path=strenv(tmpdir) + "/agent.pem"
    '

    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: cannot use TLS with a unix socket"

    rune -0 cscli machines delete with-socket
}

@test "invalid cert for agent" {
    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        .ca_cert_path=strenv(tmpdir) + "/bundle.pem" |
        .key_path=strenv(tmpdir) + "/agent_invalid-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent_invalid.pem" |
        .url="https://127.0.0.1:8080"
    '
    config_set "${CONFIG_DIR}/local_api_credentials.yaml" 'del(.login,.password)'
    ./instance-crowdsec start
    rune -1 cscli lapi status
    rune -0 cscli machines list -o json
    assert_output '[]'
}

@test "revoked cert for agent" {
    truncate_log
    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        .ca_cert_path=strenv(tmpdir) + "/bundle.pem" |
        .key_path=strenv(tmpdir) + "/agent_revoked-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent_revoked.pem" |
        .url="https://127.0.0.1:8080"
    '

    config_set "${CONFIG_DIR}/local_api_credentials.yaml" 'del(.login,.password)'
    ./instance-crowdsec start
    rune -1 cscli lapi status
    assert_log --partial "client certificate is revoked by CRL"
    assert_log --partial "client certificate for CN=localhost OU=[agent-ou] is revoked"
    rune -0 cscli machines list -o json
    assert_output '[]'
}
