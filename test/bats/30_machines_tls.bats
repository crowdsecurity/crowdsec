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

    # Root CA
    cfssl gencert \
        --initca "${CFDIR}/ca_root.json" 2>/dev/null \
        | cfssljson --bare "${tmpdir}/ca"

    # Intermediate CA
    cfssl gencert \
        --initca "${CFDIR}/ca_intermediate.json" 2>/dev/null \
        | cfssljson --bare "${tmpdir}/inter"

    cfssl sign \
        -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" \
        -config "${CFDIR}/profiles.json" -profile intermediate_ca "${tmpdir}/inter.csr" 2>/dev/null \
        | cfssljson --bare "${tmpdir}/inter"

    # Server cert for crowdsec with the intermediate
    cfssl gencert \
        -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=server "${CFDIR}/server.json" 2>/dev/null \
        | cfssljson --bare "${tmpdir}/server"

    # Client cert (valid)
    cfssl gencert \
        -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent.json" 2>/dev/null \
        | cfssljson --bare "${tmpdir}/agent"

    # Bad client cert (invalid OU)
    cfssl gencert \
        -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent_invalid.json" 2>/dev/null \
        | cfssljson --bare "${tmpdir}/agent_bad_ou"

    # Bad client cert (directly signed by the CA, it should be refused by crowdsec as it uses the intermediate)
    cfssl gencert \
        -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent.json" 2>/dev/null \
        | cfssljson --bare "${tmpdir}/agent_invalid"

    # Bad client certs (revoked)
    for cert_name in "revoked_1" "revoked_2"; do
        cfssl gencert \
            -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" \
            -config "${CFDIR}/profiles.json" -profile=client "${CFDIR}/agent.json" 2>/dev/null \
            | cfssljson --bare "${tmpdir}/${cert_name}"

        cfssl certinfo \
            -cert "${tmpdir}/${cert_name}.pem" \
            | jq -r '.serial_number' > "${tmpdir}/serials_${cert_name}.txt"
    done

    # Generate separate CRL blocks and concatenate them
    for cert_name in "revoked_1" "revoked_2"; do
        echo '-----BEGIN X509 CRL-----' > "${tmpdir}/crl_${cert_name}.pem"
        cfssl gencrl \
            "${tmpdir}/serials_${cert_name}.txt" "${tmpdir}/ca.pem" "${tmpdir}/ca-key.pem" \
            >> "${tmpdir}/crl_${cert_name}.pem"
        echo '-----END X509 CRL-----' >> "${tmpdir}/crl_${cert_name}.pem"
    done
    cat "${tmpdir}/crl_revoked_1.pem" "${tmpdir}/crl_revoked_2.pem" >"${tmpdir}/crl.pem"

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
    # we have two certificates revoked by different CRL blocks
    for cert_name in "revoked_1" "revoked_2"; do
        truncate_log
        cert_name="$cert_name" config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
            .ca_cert_path=strenv(tmpdir) + "/bundle.pem" |
            .key_path=strenv(tmpdir) + "/" + strenv(cert_name) + "-key.pem" |
            .cert_path=strenv(tmpdir) + "/" + strenv(cert_name) + ".pem" |
            .url="https://127.0.0.1:8080"
        '

        config_set "${CONFIG_DIR}/local_api_credentials.yaml" 'del(.login,.password)'
        ./instance-crowdsec start
        rune -1 cscli lapi status
        assert_log --partial "client certificate is revoked by CRL"
        assert_log --partial "client certificate for CN=localhost OU=[agent-ou] is revoked"
        rune -0 cscli machines list -o json
        assert_output '[]'
        ./instance-crowdsec stop
    done
}

# vvv this test must be last, or it can break the ones that follow

@test "allowed_ou can't contain an empty string" {
    config_set '
        .common.log_media="stdout" |
        .api.server.tls.agents_allowed_ou=["agent-ou", ""]
    '
    rune -1 wait-for "$CROWDSEC"
    assert_stderr --partial "allowed_ou configuration contains invalid empty string"
}

# ^^^ this test must be last, or it can break the ones that follow
