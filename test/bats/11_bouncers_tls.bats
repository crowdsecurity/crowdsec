#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

# root: root CA
# inter: intermediate CA
# inter_rev: intermediate CA revoked by root (CRL3)
# leaf: valid client cert
# leaf_rev1: client cert revoked by inter (CRL1)
# leaf_rev2: client cert revoked by inter (CRL2)
# leaf_rev3: client cert (indirectly) revoked by root
#
# CRL1: inter revokes leaf_rev1
# CRL2: inter revokes leaf_rev2
# CRL3: root revokes inter_rev
# CRL4: root revokes leaf, but is ignored

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load

    tmpdir="$BATS_FILE_TMPDIR"
    export tmpdir

    CFDIR="$BATS_TEST_DIRNAME/testdata/cfssl"
    export CFDIR

    # Root CA
    cfssl gencert -loglevel 2 \
        --initca "$CFDIR/ca_root.json" \
        | cfssljson --bare "$tmpdir/root"

    # Intermediate CAs (valid or revoked)
    for cert in "inter" "inter_rev"; do
        cfssl gencert -loglevel 2 \
            --initca "$CFDIR/ca_intermediate.json" \
            | cfssljson --bare "$tmpdir/$cert"

        cfssl sign -loglevel 2 \
            -ca "$tmpdir/root.pem" -ca-key "$tmpdir/root-key.pem" \
            -config "$CFDIR/profiles.json" -profile intermediate_ca "$tmpdir/$cert.csr" \
            | cfssljson --bare "$tmpdir/$cert"
    done

    # Server cert for crowdsec with the intermediate
    cfssl gencert -loglevel 2 \
        -ca "$tmpdir/inter.pem" -ca-key "$tmpdir/inter-key.pem" \
        -config "$CFDIR/profiles.json" -profile=server "$CFDIR/server.json" \
        | cfssljson --bare "$tmpdir/server"

    # Client certs (valid or revoked)
    for cert in "leaf" "leaf_rev1" "leaf_rev2"; do
        cfssl gencert -loglevel 3 \
            -ca "$tmpdir/inter.pem" -ca-key "$tmpdir/inter-key.pem" \
            -config "$CFDIR/profiles.json" -profile=client \
            "$CFDIR/bouncer.json" \
            | cfssljson --bare "$tmpdir/$cert"
    done

    # Client cert (by revoked inter)
    cfssl gencert -loglevel 3 \
        -ca "$tmpdir/inter_rev.pem" -ca-key "$tmpdir/inter_rev-key.pem" \
        -config "$CFDIR/profiles.json" -profile=client \
        "$CFDIR/bouncer.json" \
        | cfssljson --bare "$tmpdir/leaf_rev3"

    # Bad client cert (invalid OU)
    cfssl gencert -loglevel 3 \
        -ca "$tmpdir/inter.pem" -ca-key "$tmpdir/inter-key.pem" \
        -config "$CFDIR/profiles.json" -profile=client \
        "$CFDIR/bouncer_invalid.json" \
        | cfssljson --bare "$tmpdir/leaf_bad_ou"

    # Bad client cert (directly signed by the CA, it should be refused by crowdsec as it uses the intermediate)
    cfssl gencert -loglevel 3 \
        -ca "$tmpdir/root.pem" -ca-key "$tmpdir/root-key.pem" \
        -config "$CFDIR/profiles.json" -profile=client \
        "$CFDIR/bouncer.json" \
        | cfssljson --bare "$tmpdir/leaf_invalid"

    truncate -s 0 "$tmpdir/crl.pem"

    # Revoke certs
    {
        echo '-----BEGIN X509 CRL-----'
        cfssl gencrl \
            <(cert_serial_number "$tmpdir/leaf_rev1.pem") \
            "$tmpdir/inter.pem" \
            "$tmpdir/inter-key.pem"
        echo '-----END X509 CRL-----'

        echo '-----BEGIN X509 CRL-----'
        cfssl gencrl \
            <(cert_serial_number "$tmpdir/leaf_rev2.pem") \
            "$tmpdir/inter.pem" \
            "$tmpdir/inter-key.pem"
        echo '-----END X509 CRL-----'

        echo '-----BEGIN X509 CRL-----'
        cfssl gencrl \
            <(cert_serial_number "$tmpdir/inter_rev.pem") \
            "$tmpdir/root.pem" \
            "$tmpdir/root-key.pem"
        echo '-----END X509 CRL-----'

        echo '-----BEGIN X509 CRL-----'
        cfssl gencrl \
            <(cert_serial_number "$tmpdir/leaf.pem") \
            "$tmpdir/root.pem" \
            "$tmpdir/root-key.pem"
        echo '-----END X509 CRL-----'
    } >> "$tmpdir/crl.pem"

    cat "$tmpdir/root.pem" "$tmpdir/inter.pem" > "$tmpdir/bundle.pem"

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

@test "simulate a bouncer request with a valid cert" {
    rune -0 curl --fail-with-body -sS \
        --cert "$tmpdir/leaf.pem" \
        --key "$tmpdir/leaf-key.pem" \
        --cacert "$tmpdir/bundle.pem" \
        https://localhost:8080/v1/decisions\?ip=42.42.42.42
    assert_output "null"
    refute_stderr
    rune -0 cscli bouncers list -o json
    rune -0 jq '. | length' <(output)
    assert_output '1'
    rune -0 cscli bouncers list -o json
    rune -0 jq -r '.[] | .name' <(output)
    assert_output "localhost@127.0.0.1"
    rune cscli bouncers delete localhost@127.0.0.1
}

@test "a bouncer authenticated with TLS can send metrics" {
    payload=$(yq -o j <<-EOT
	remediation_components: []
	log_processors: []
	EOT
    )

    # with mutual authentication there is no api key, so it's detected as RC if user agent != crowdsec

    rune -22 curl --fail-with-body -sS \
        --cert "$tmpdir/leaf.pem" \
        --key "$tmpdir/leaf-key.pem" \
        --cacert "$tmpdir/bundle.pem" \
        https://localhost:8080/v1/usage-metrics -X POST --data "$payload"
    assert_stderr --partial 'error: 400'
    assert_json '{message: "Missing remediation component data"}'

    rune -22 curl --fail-with-body -sS \
        --cert "$tmpdir/leaf.pem" \
        --key "$tmpdir/leaf-key.pem" \
        --cacert "$tmpdir/bundle.pem" \
        --user-agent "crowdsec/someversion" \
        https://localhost:8080/v1/usage-metrics -X POST --data "$payload"
    assert_stderr --partial 'error: 401'
    assert_json '{code:401, message: "cookie token is empty"}'

    rune cscli bouncers delete localhost@127.0.0.1
}

@test "simulate a bouncer request with an invalid cert" {
    rune -77 curl --fail-with-body -sS \
        --cert "$tmpdir/leaf_invalid.pem" \
        --key "$tmpdir/leaf_invalid-key.pem" \
        --cacert "$tmpdir/root-key.pem" \
        https://localhost:8080/v1/decisions\?ip=42.42.42.42
    assert_stderr --partial 'error setting certificate file'
    rune -0 cscli bouncers list -o json
    assert_output "[]"
}

@test "simulate a bouncer request with an invalid OU" {
    rune -22 curl --fail-with-body -sS \
        --cert "$tmpdir/leaf_bad_ou.pem" \
        --key "$tmpdir/leaf_bad_ou-key.pem" \
        --cacert "$tmpdir/bundle.pem" \
        https://localhost:8080/v1/decisions\?ip=42.42.42.42
    assert_json '{message: "access forbidden"}'
    assert_stderr --partial 'error: 403'
    rune -0 cscli bouncers list -o json
    assert_output "[]"
}

@test "simulate a bouncer request with a revoked certificate" {
    # we have two certificates revoked by different CRL blocks
    # we connect twice to test the cache too
    for cert in "leaf_rev1" "leaf_rev2" "leaf_rev1" "leaf_rev2"; do
        truncate_log
        rune -22 curl --fail-with-body -sS \
            --cert "$tmpdir/$cert.pem" \
            --key "$tmpdir/$cert-key.pem" \
            --cacert "$tmpdir/bundle.pem" \
            https://localhost:8080/v1/decisions\?ip=42.42.42.42
        assert_log --partial "certificate revoked by CRL"
        assert_json '{message: "access forbidden"}'
        assert_stderr --partial "error: 403"
        rune -0 cscli bouncers list -o json
        assert_output "[]"
    done
}

# vvv this test must be last, or it can break the ones that follow

@test "allowed_ou can't contain an empty string" {
    ./instance-crowdsec stop
    config_set '
        .common.log_media="stdout" |
        .api.server.tls.bouncers_allowed_ou=["bouncer-ou", ""]
    '
    rune -1 wait-for "$CROWDSEC"
    assert_stderr --partial "allowed_ou configuration contains invalid empty string"
}

# ^^^ this test must be last, or it can break the ones that follow
