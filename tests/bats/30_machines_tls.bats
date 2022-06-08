#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

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
    #gen client cert for the agent
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/agent.json 2>/dev/null | cfssljson --bare "${tmpdir}/agent"
    #gen client cert for the agent with an invalid OU
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/agent_invalid.json 2>/dev/null | cfssljson --bare "${tmpdir}/agent_bad_ou"
    #gen client cert for the agent directly signed by the CA, it should be refused by crowdsec as uses the intermediate
    cfssl gencert -ca "${tmpdir}/ca.pem" -ca-key "${tmpdir}/ca-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/agent.json 2>/dev/null | cfssljson --bare "${tmpdir}/agent_invalid" 
    
    cfssl gencert -ca "${tmpdir}/inter.pem" -ca-key "${tmpdir}/inter-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/agent.json 2>/dev/null | cfssljson --bare "${tmpdir}/agent_revoked"
    serial="$(openssl x509 -noout -serial -in ${tmpdir}/agent_revoked.pem | cut -d '=' -f2)"
    echo "ibase=16; $serial" | bc > "${tmpdir}/serials.txt"
    cfssl gencrl "${tmpdir}/serials.txt" "${tmpdir}/ca.pem" "${tmpdir}/ca-key.pem" | base64 -d | openssl crl -inform DER -out "${tmpdir}/crl.pem"


    yq '
        .api.server.tls.cert_file=strenv(tmpdir) + "/server.pem" |
        .api.server.tls.key_file=strenv(tmpdir) + "/server-key.pem" |
        .api.server.tls.ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .api.server.tls.crl_path=strenv(tmpdir) + "/crl.pem" | 
        .api.server.tls.agents_allowed_ou=["agent-ou"]
    ' -i "${CONFIG_YAML}"

}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    cscli machines delete githubciXXXXXXXXXXXXXXXXXXXXXXXX
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "$FILE invalid OU for agent" {
    CONFIG_DIR=$(dirname ${CONFIG_YAML})

    yq '
        .ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .key_path=strenv(tmpdir) + "/agent_bad_ou-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent_bad_ou.pem" |
        .url="https://127.0.0.1:8080"
    ' -i "${CONFIG_DIR}/local_api_credentials.yaml"

    yq 'del(.login)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    yq 'del(.password)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    ./instance-crowdsec start
    #let the agent start
    sleep 2
    run -0 cscli machines list -o json
    assert_output '[]'
}

@test "$FILE we have exactly one machine registered with TLS" {
    CONFIG_DIR=$(dirname ${CONFIG_YAML})

    yq '
        .ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .key_path=strenv(tmpdir) + "/agent-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent.pem" |
        .url="https://127.0.0.1:8080"
    ' -i "${CONFIG_DIR}/local_api_credentials.yaml"

    yq 'del(.login)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    yq 'del(.password)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    ./instance-crowdsec start
    #let the agent start
    sleep 2
    run -0 cscli machines list -o json
    run -0 jq -c '[. | length, .[0].machineId[0:32], .[0].isValidated, .[0].ipAddress, .[0].auth_type]' <(output)

    assert_output '[1,"localhost@127.0.0.1",true,"127.0.0.1","tls"]'
    cscli machines delete localhost@127.0.0.1

    ./instance-crowdsec stop
}


@test "$FILE invalid cert for agent" {
    CONFIG_DIR=$(dirname ${CONFIG_YAML})

    yq '
        .ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .key_path=strenv(tmpdir) + "/agent_invalid-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent_invalid.pem" |
        .url="https://127.0.0.1:8080"
    ' -i "${CONFIG_DIR}/local_api_credentials.yaml"

    yq 'del(.login)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    yq 'del(.password)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    ./instance-crowdsec start
    #let the agent start
    sleep 2
    run -0 cscli machines list -o json
    assert_output '[]'
}

@test "$FILE revoked cert for agent" {
    CONFIG_DIR=$(dirname ${CONFIG_YAML})

    yq '
        .ca_cert_path=strenv(tmpdir) + "/inter.pem" |
        .key_path=strenv(tmpdir) + "/agent_revoked-key.pem" |
        .cert_path=strenv(tmpdir) + "/agent_revoked.pem" |
        .url="https://127.0.0.1:8080"
    ' -i "${CONFIG_DIR}/local_api_credentials.yaml"

    yq 'del(.login)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    yq 'del(.password)' -i "${CONFIG_DIR}/local_api_credentials.yaml"
    ./instance-crowdsec start
    #let the agent start
    sleep 2
    run -0 cscli machines list -o json
    assert_output '[]'
}