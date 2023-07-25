#!/bin/sh

## DB_BACKEND is required, because even if it has a sensible default (sqlite)
## all other variables can have an empty value. So if DB_BACKEND is missing you
## may have forgot to set the environment for the test run.
## One of "sqlite", "postgres", "pgx", "mysql"
DB_BACKEND=sqlite

## Set this to test a binary package (deb, rpm..). If missing or false,
## crowdsec will be built from sources and tested an non-root without installation.
# PACKAGE_TESTING=true

## The URL of a crowdsec repository with the test scripts.
# TEST_SUITE_GIT="https://github.com/crowdsecurity/crowdsec"

## The branch, tag or commit of the test scripts.
# TEST_SUITE_VERSION="master"

## The path to a crowdsec.zip file containing the crowdsec sources with test scripts.
## Overrides TEST_SUITE_GIT and TEST_SUITE_VERSION.
# TEST_SUITE_ZIP="/tmp/crowdsec.zip"

## TEST_PACKAGE_VERSION_DEB is the version of the package under test.
## Can be different from TEST_PACKAGE_VERSION_RPM in case of stable releases (no '-1' suffix).
# TEST_PACKAGE_VERSION_DEB=1.4.1

## TEST_PACKAGE_VERSION_RPM is the version of the package under test.
## Can be different from TEST_PACKAGE_VERSION_DEB in case of stable releases (rpm requires a '-1' suffix).
# TEST_PACKAGE_VERSION_RPM=1.4.1-1

## The path to a crowdsec binary package (.deb, .rpm..). If both this and TEST_PACKAGE_VERSION_* are set,
## the package from TEST_PACKAGE_VERSION_* will be installed first, then replaced by the package in the
## provided file. This is a way to test upgrades.
# TEST_PACKAGE_FILE="/tmp/crowdsec.deb"

## The path to a bundle with all the .deb and .rpm packages, split by architecture, distribution and version (see README).
# TEST_PACKAGE_DIR=/path/to/packages/1.4.1-rc1

## A comma-separated list of test scripts to skip. Example: "02_nolapi.bats,03_noagent.bats"
# TEST_SKIP=

export DB_BACKEND
export PACKAGE_TESTING
export TEST_SUITE_GIT
export TEST_SUITE_VERSION
export TEST_SUITE_ZIP
export TEST_PACKAGE_VERSION_DEB
export TEST_PACKAGE_VERSION_RPM
export TEST_PACKAGE_FILE
export TEST_PACKAGE_DIR
export TEST_SKIP
