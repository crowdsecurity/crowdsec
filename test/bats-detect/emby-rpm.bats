#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    load "${BATS_TEST_DIRNAME}/lib/setup_file_detect.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
    rpm-remove  emby-server
}

setup() {
    if ! command -v dnf >/dev/null; then
        skip 'not a redhat-like system'
    fi
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
}

#----------

@test "emby: detect unit (fail)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    refute_line 'emby-systemd'
}

@test "emby: install" {
    # https://emby.media/linux-server.html
    version=4.7.6.0
    filename="emby-server-rpm_${version}_x86_64.rpm"
    # don't download twice
    run -0 curl -1sSLf "https://github.com/MediaBrowser/Emby.Releases/releases/download/${version}/${filename}" -o "${CACHEDIR}/${filename}"
    run -0 rpm-install "${CACHEDIR}/${filename}"
    run -0 sudo systemctl enable emby-server.service
}

@test "emby: detect unit (succeed)" {
    run -0 cscli setup detect
    run -0 jq -r '.setup | .[].detected_service' <(output)
    assert_line 'emby-systemd'
}

@test "emby: install detected collection" {
    run -0 cscli setup detect
    run -0 cscli setup install-hub <(output)
}
