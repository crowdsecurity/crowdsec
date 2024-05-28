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
    cfssl gencert -loglevel 2 \
        --initca "${CFDIR}/ca_root.json" \
        | cfssljson --bare "${tmpdir}/root"

    # Intermediate CAs (valid or revoked)
    for cert_name in "inter" "inter_rev"; do
        cfssl gencert -loglevel 2 \
            --initca "${CFDIR}/ca_intermediate.json" \
            | cfssljson --bare "${tmpdir}/${cert_name}"

        cfssl sign -loglevel 2 \
            -ca "${tmpdir}/root.pem" -ca-key "${tmpdir}/root-key.pem" \
            -config "${CFDIR}/profiles.json" -profile intermediate_ca "${tmpdir}/${cert_name}.csr" \
            | cfssljson --bare "${tmpdir}/${cert_name}"
    done

    # Server cert for crowdsec with the intermediate
    cfssl gencert -loglevel 2 \
        -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=server "${CFDIR}/server.json" \
        | cfssljson --bare "${tmpdir}/server"

    # Client certs (valid or revoked)
    for cert_name in "leaf" "leaf_rev1" "leaf_rev2"; do
        cfssl gencert -loglevel 3 \
            -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" \
            -config "${CFDIR}/profiles.json" -profile=client \
            "${CFDIR}/agent.json" \
            | cfssljson --bare "${tmpdir}/${cert_name}"
    done

    # Client cert (by revoked inter)
    cfssl gencert -loglevel 3 \
        -ca "${tmpdir}/inter_rev.pem" -ca-key "${tmpdir}/inter_rev-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=client \
        "${CFDIR}/agent.json" \
        | cfssljson --bare "${tmpdir}/leaf_rev3"

    # Bad client cert (invalid OU)
    cfssl gencert -loglevel 3 \
        -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=client \
        "${CFDIR}/agent_invalid.json" \
        | cfssljson --bare "${tmpdir}/leaf_bad_ou"

    # Bad client cert (directly signed by the CA, it should be refused by crowdsec as it uses the intermediate)
    cfssl gencert -loglevel 3 \
        -ca "${tmpdir}/root.pem" -ca-key "${tmpdir}/root-key.pem" \
        -config "${CFDIR}/profiles.json" -profile=client \
        "${CFDIR}/agent.json" \
        | cfssljson --bare "${tmpdir}/leaf_invalid"

    truncate -s 0 "${tmpdir}/crl.pem"

    # Revoke certs
    {
        echo '-----BEGIN X509 CRL-----'
        cfssl gencrl \
            <(cfssl certinfo -cert "${tmpdir}/leaf_rev1.pem" | jq -r '.serial_number') \
            "${tmpdir}/inter.pem" \
            "${tmpdir}/inter-key.pem"
        echo '-----END X509 CRL-----'

        echo '-----BEGIN X509 CRL-----'
        cfssl gencrl \
            <(cfssl certinfo -cert "${tmpdir}/leaf_rev2.pem" | jq -r '.serial_number') \
            "${tmpdir}/inter.pem" \
            "${tmpdir}/inter-key.pem"
        echo '-----END X509 CRL-----'

        echo '-----BEGIN X509 CRL-----'
        cfssl gencrl \
            <(cfssl certinfo -cert "${tmpdir}/inter_rev.pem" | jq -r '.serial_number') \
            "${tmpdir}/root.pem" \
            "${tmpdir}/root-key.pem"
        echo '-----END X509 CRL-----'
    } >> "${tmpdir}/crl.pem"

    cat "${tmpdir}/root.pem" "${tmpdir}/inter.pem" > "${tmpdir}/bundle.pem"

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
        .key_path=strenv(tmpdir) + "/leaf_bad_ou-key.pem" |
        .cert_path=strenv(tmpdir) + "/leaf_bad_ou.pem" |
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
        .key_path=strenv(tmpdir) + "/leaf-key.pem" |
        .cert_path=strenv(tmpdir) + "/leaf.pem" |
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
        .key_path=strenv(tmpdir) + "/leaf-key.pem"
    '

    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: cannot use TLS with a unix socket"

    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        del(.key_path) |
        .cert_path=strenv(tmpdir) + "/leaf.pem"
    '

    rune -1 cscli lapi status
    assert_stderr --partial "loading api client: cannot use TLS with a unix socket"

    rune -0 cscli machines delete with-socket
}

@test "invalid cert for agent" {
    config_set "${CONFIG_DIR}/local_api_credentials.yaml" '
        .ca_cert_path=strenv(tmpdir) + "/bundle.pem" |
        .key_path=strenv(tmpdir) + "/leaf_invalid-key.pem" |
        .cert_path=strenv(tmpdir) + "/leaf_invalid.pem" |
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
    for cert_name in "leaf_rev1" "leaf_rev2"; do
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
