#!/usr/bin/env bash

TESTDATA="${BATS_TEST_DIRNAME}/testdata"
export TESTDATA

CACHEDIR="${TESTDATA}/.cache"
export CACHEDIR

mkdir -p "${CACHEDIR}"

DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

# avoid warnings in stderr, especially from perl modules
LC_ALL=C
export LC_ALL

deb-install() {
    # use aptitude to reliably purge dependencies too
    sudo aptitude install "$@" -yq >/dev/null
    # this does not work well enough
    # sudo apt-get -qq -y -o Dpkg:Use-Pty=0 install "$@" >/dev/null
    # sudo apt-mark auto "$@"
}
export -f deb-install

deb-update() {
    sudo apt-get -qq -y -o Dpkg:Use-Pty=0 update
}
export -f deb-update

deb-remove() {
    for pkg in "$@"; do
        if dpkg -s "${pkg}" >/dev/null 2>&1; then
            # use aptitude to reliably purge dependencies too
            sudo aptitude purge "${pkg}" -yq >/dev/null
            # this does not work well enough
            # sudo apt-get -qq -y purge --auto-remove "${pkg}" >/dev/null
        fi
    done
}
export -f deb-remove

rpm-install() {
    sudo dnf -q -y install "$@"
}
export -f rpm-install

rpm-remove() {
    # don't fail if dnf does not exist (teardown is called on deb distros too)
    if command -v dnf >/dev/null; then
        sudo dnf -q -y remove "$@" >/dev/null
    fi
}
export -f rpm-remove
