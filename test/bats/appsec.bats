#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    CONFIG_DIR=$(dirname "$CONFIG_YAML")
    export CONFIG_DIR

    ACQUIS_DIR=$(config_get '.crowdsec_service.acquisition_dir')
    export ACQUIS_DIR
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    mkdir -p "$ACQUIS_DIR"
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "invalid configuration" {
    config_set '.common.log_media="stdout"'

    cat > "$ACQUIS_DIR"/appsec.yaml <<-EOT
	source: appsec
	EOT

    rune -1 wait-for "$CROWDSEC"
    assert_stderr --partial "crowdsec init: while loading acquisition config: missing labels in $ACQUIS_DIR/appsec.yaml (position 0)"

    cat > "$ACQUIS_DIR"/appsec.yaml <<-EOT
	source: appsec
	labels:
	  type: appsec
	EOT

    rune -1 wait-for "$CROWDSEC"
    assert_stderr --partial "crowdsec init: while loading acquisition config: while configuring datasource of type appsec from $ACQUIS_DIR/appsec.yaml (position 0): unable to parse appsec configuration: appsec_config or appsec_config_path must be set"
}

@test "appsec allow and ban" {
    config_set '.common.log_media="stdout"'

    rune -0 cscli collections install crowdsecurity/appsec-virtual-patching
    rune -0 cscli collections install crowdsecurity/appsec-generic-rules

    socket="$BATS_TEST_TMPDIR"/sock

    cat > "$ACQUIS_DIR"/appsec.yaml <<-EOT
	source: appsec
	listen_socket: $socket
	labels:
	  type: appsec
	appsec_config: crowdsecurity/appsec-default
	EOT

    rune -0 wait-for \
        --err "Appsec Runner ready to process event" \
        "$CROWDSEC"

    assert_stderr --partial "loading inband rule crowdsecurity/base-config"
    assert_stderr --partial "loading inband rule crowdsecurity/vpatch-*"
    assert_stderr --partial "loading inband rule crowdsecurity/generic-*"
    assert_stderr --partial "Created 1 appsec runners"
    assert_stderr --partial "Appsec Runner ready to process event"

    ./instance-crowdsec start

    rune -0 cscli bouncers add appsecbouncer --key appkey

    # appsec will perform a HEAD request to validate.
    # If it fails, check downstream with:
    #
    # lapisocket=$(config_get '.api.server.listen_socket')
    # rune -0 curl -sS --fail-with-body --unix-socket "$lapisocket" -H "X-Api-Key: appkey" "http://fakehost/v1/decisions/stream"
    # assert_json '{deleted:null,new:null}'

    rune -0 curl -sS --fail-with-body --unix-socket "$socket" \
        -H "x-crowdsec-appsec-api-key: appkey" \
        -H "x-crowdsec-appsec-ip: 1.2.3.4" \
        -H 'x-crowdsec-appsec-uri: /' \
        -H 'x-crowdsec-appsec-host: foo.com' \
        -H 'x-crowdsec-appsec-verb: GET' \
        'http://fakehost'

    assert_json '{action:"allow",http_status:200}'

    rune -22 curl -sS --fail-with-body --unix-socket "$socket" \
        -H "x-crowdsec-appsec-api-key: appkey" \
        -H "x-crowdsec-appsec-ip: 1.2.3.4" \
        -H 'x-crowdsec-appsec-uri: /.env' \
        -H 'x-crowdsec-appsec-host: foo.com' \
        -H 'x-crowdsec-appsec-verb: GET' \
        'http://fakehost'

    assert_json '{action:"ban",http_status:403}'
}

@test "TLS connection to lapi, own CA" {
    tmpdir="$BATS_FILE_TMPDIR"

    CFDIR="$BATS_TEST_DIRNAME/testdata/cfssl"

    # Root CA
    cfssl gencert -loglevel 2 \
        --initca "$CFDIR/ca_root.json" \
        | cfssljson --bare "$tmpdir/root"

    # Intermediate CA
    cfssl gencert -loglevel 2 \
        --initca "$CFDIR/ca_intermediate.json" \
        | cfssljson --bare "$tmpdir/inter"

    cfssl sign -loglevel 2 \
        -ca "$tmpdir/root.pem" -ca-key "$tmpdir/root-key.pem" \
        -config "$CFDIR/profiles.json" -profile intermediate_ca "$tmpdir/inter.csr" \
        | cfssljson --bare "$tmpdir/inter"

    # Server cert for crowdsec with the intermediate
    cfssl gencert -loglevel 2 \
        -ca "$tmpdir/inter.pem" -ca-key "$tmpdir/inter-key.pem" \
        -config "$CFDIR/profiles.json" -profile=server "$CFDIR/server.json" \
        | cfssljson --bare "$tmpdir/server"

    cat "$tmpdir/root.pem" "$tmpdir/inter.pem" > "$tmpdir/bundle.pem"

    export tmpdir
    config_set '
        .api.server.tls.cert_file=strenv(tmpdir) + "/server.pem" |
        .api.server.tls.key_file=strenv(tmpdir) + "/server-key.pem" |
        .api.server.tls.ca_cert_path=strenv(tmpdir) + "/inter.pem"
    '

    rune -0 cscli collections install crowdsecurity/appsec-virtual-patching
    rune -0 cscli collections install crowdsecurity/appsec-generic-rules

    socket="$BATS_TEST_TMPDIR"/sock

    cat > "$ACQUIS_DIR"/appsec.yaml <<-EOT
	source: appsec
	listen_socket: $socket
	labels:
	  type: appsec
	appsec_config: crowdsecurity/appsec-default
	EOT

    config_set "$CONFIG_DIR/local_api_credentials.yaml" '
        .url="https://127.0.0.1:8080" |
        .ca_cert_path=strenv(tmpdir) + "/bundle.pem"
    '

    ./instance-crowdsec start

    rune -0 cscli bouncers add appsecbouncer --key appkey

    rune -0 curl -sS --fail-with-body --unix-socket "$socket" \
        -H "x-crowdsec-appsec-api-key: appkey" \
        -H "x-crowdsec-appsec-ip: 1.2.3.4" \
        -H 'x-crowdsec-appsec-uri: /' \
        -H 'x-crowdsec-appsec-host: foo.com' \
        -H 'x-crowdsec-appsec-verb: GET' \
        'http://fakehost'

    assert_json '{action:"allow",http_status:200}'
}
