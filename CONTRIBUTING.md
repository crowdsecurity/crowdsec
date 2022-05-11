# Contributing to CrowdSec <!-- omit in toc -->

There are many ways to contribute to CrowdSec. Already by using our product, you are contributing to the data pool by reporting attacks to your systems, and this is what makes us (and you!) special.

Going further, you can contribute scenarios, parsers and collections.

The rest of this document will focus on contributions to the crowdsecurity/crowdsec repository, style guides and branch policy.

## Reporting bugs

TBD

## Testing

There are three types of tests. You can run them anytime on your environment,
and they are also run from the GitHub CI.

### Go tests

Go test include unit and integration tests written in the `*_test.go` files,
you need a working [localstack](https://github.com/localstack/localstack)
environment and run a test suite with `make test`.

XXX TODO: how to run localstack

### Bats tests

These are documented in [./tests/README.md](./tests/README.md).
They are easier to write than the Go tests, but can only test
a binary's external behavior. Run with `make bats-all`.

### Hub tests

These are testing the parsers, scenarios, etc. They are run from the bats tests
for convenience but actually defined in [the Hub
repository](https://github.com/crowdsecurity/hub/tree/master/.tests).
Run with `make bats-build bats-fixture` once, then `make bats-test-hub`.

## Git workflow / branch management

We receive contributions on the _master_ branch (or _main_, in recent repositories). To contribute, fork the repository, commit the code in a dedicated branch and ask for a Pull Request. By default it will target the master branch on the upstream repository, so in most cases you don't have to change anything. It will be reviewed by the core team and merged when ready, possibly after some changes. It is recommended to open [an Issue linked to the PR](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) in order to discuss it and track its progression.

You may also receive feedback from the CI scripts (directory [.github/workflows](.github/workflows)) that run a series of linters and tests. You are encouraged to run these on your environment as well, before committing (see the "Testing" section above, and "Style guide" below).

## Release branches

When we decide to start working on a major or minor release (for example 1.5) we create a 1.5.x branch from master. New contributions are always on the master, but from time to time the master is merged to the release branch. The upcoming release branch does not receive code from anywhere than the master branch.

As work progresses on the release branch, we eventually create pre-release tags (ex. 1.5.0-rc1) and finally a release tag (1.5.0). At this point, we create the Release (source tar, zip, binary and static), and push the button on the Goldberg Machine to publish the binary packages.

This is where we create the 1.6.x branch and we put the 1.5.x in maintenance mode. A maintenance branch is divorced from master, and can receive code from branches other than master, to allow for backporting features and fixes. These lead eventually to _patch versions_ (1.5.1, 1.5.2) which correspond to git tags but don't have dedicated branches.

## Style guides

### Go

TBD (gofmt, golangci-lint)

### Python

TBD (black, flake8)

### Bash, bats

TBD (shellcheck, shfmt, checkbashisms)

## Code Of Conduct

TBD
