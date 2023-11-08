# Ansible playbooks for functional testing

These playbooks allow you to test crowdsec in a real environment, where the
application is running as root, deployed with the OS package manager, and
uses the standard init system for the distribution (systemd or other).

This way, you can test not only the application's feature but also the packaging
boilerplate, integration scripts, and compatibility with new distribution releases,
operating systems, or architectures.

The ansible hosts should be expendable machines with at least 1GB RAM, do not
expect them to be stable if you use them for anything else after the tests.

Install (or update) the requirements with `ansible-galaxy install -r requirements.yml --force`.

There are several Ansible playbooks. You can use `run-all.yml` to configure the
installation and run the tests, or run the playbooks separately to iterate while developing.

- run-all.yml: run the other playbooks in the correct order.

- provision-dependencies.yml: install the bats requirements (bash, netcat, cfssl, etc.), compilers, and database.

- provision-test-suite.yml: install the tests scripts and bats environment, and the crowdsec sources if we want to build the `crowdsec under test`.

- install_binary_package.yml: install the `crowdsec under test` from a binary package (already released or not).

- prepare-tests.yml: create the test fixture data.

- run-tests.yml: run the functional tests. This is not idempotent and can be run multiple times.

The tasks use the following environment variables. They must be exported or
ansible won't be able to see them.

- `TEST_SUITE_GIT` (default "https://github.com/crowdsecurity/crowdsec"),
  `TEST_SUITE_VERSION` (default "master"): repo URL and branch/tag/commit of
  the crowdsec sources containing the test fixture and scripts.

- `TEST_SUITE_ZIP`: optional, archive of a `crowdsecurity/crowdsec` repository
  containing the test fixture and scripts. Overrides `TEST_SUITE_GIT` and
  `TEST_SUITE_VERSION`. It can be created with `zip -r crowdsec.zip .` from
  the root directory of the repository.

- `DB_BACKEND`: Required. Set to "sqlite", "pgx", "mysql", "postgres".
  Postgres is automatically provisioned when required. There is no
  provisioning code for mysql/mariadb yet, but it can be added.

- `PACKAGE_TESTING`: when set to false or not defined, the crowdsec binaries
  to be tested are built from the sources that come from `TEST_SUITE_GIT` or
  `TEST_SUITE_ZIP`. Crowdsec is then run as non-root, in a local directory.
  This is basically a fancy wrapper to run `make bats-test` in a vm.
  When `PACKAGE_TESTING` is set to true, however, crowdsec is installed from
  a binary package (see variables below), it is run as root from systemd (or
  equivalent) and uses the system-wide `/etc/crowdsec` and `/var/lib`
  directories to store the test data.

- `TEST_PACKAGE_VERSION_DEB`, `TEST_PACKAGE_VERSION_RPM`: Optional, the
  version of the package under test (ex. "1.4.0-rc5"), can be in the
  packagecloud "stable" or "testing" repository. Requires
  `PACKAGE_TESTING=true`. You must set both variables to reuse the same set of
  variables for Debian and RedHat-based distributions, because stable releases
  require a package version suffix in the RPM file names.

- `TEST_PACKAGE_FILE`: optional, file pointing to the package under test (.deb,
  .rpm, .pkg...). It can be a glob expression but it must match a single file,
  and the pattern works only on the filename. If both `TEST_PACKAGE_VERSION_*`
  and `TEST_PACKAGE_FILE` are provided, both are be installed (to test upgrades
  for example). Requires `PACKAGE_TESTING=true`

- `TEST_PACKAGE_DIR`: optional (but conflicts with `TEST_PACKAGE_FILE`), the path
  to a directory containing packages with the following layout:

  For DEB: `{{ package_dir }}/{{ ansible_distribution_release }}/crowdsec_*_{{ ansible_architecture.replace('x86_64', 'amd64') }}.deb`
  For RPM: `{{ package_dir }}/{{ releasever }}/RPMS/{{ ansible_architecture }}/crowdsec-*.{{ releasever }}.{{ ansible_architecture }}.rpm`

- `TEST_SKIP`: optional, comma-separated list of scripts that won't be executed.
  Example: `TEST_SKIP=02_nolapi.bats,03_noagent.bats`

## Running tests with Vagrant + Ansible

You don't need Vagrant to run the ansible tests, if you can manage your own
vm creation and inventory.

However, to avoid relying on (and paying for..) a public cloud, we wrote vagrant
configuration files for the most common distributions we support.

To test with Vagrant, you need to:

- have a working libvirt environment (if you can use virt-manager to create VMs, you're golden)

- install the vagrant-libvirt plugin (`vagrant plugin install vagrant-libvirt`.
  If it complains about gem versions, blame Ruby and see if you can remove some
  other conflicting plugin).

- copy one of the `./env/*.sh` scripts to `environment.sh`, edit to your
  needs, and execute it with "source environment.sh"

- `cd vagrant/<distro-of-your-choice>`

- `vagrant up --no-provision; vagrant provision`. The first command creates
  the VM, the second installs all the dependencies, test suite and package
  under test, then runs the tests. If you run a plain `vagrant up`, it does
  everything with a single command, but also destroys the VM in case of test
  failure so you are left with nothing to debug.

- `vagrant destroy` when you want to remove the VM. If you want to free up the
  space taken by the base VM images, they are in
  `/var/lib/libvirt/images/*VAGRANT*`

The above steps are automated in the script `./prepare-run` (requires bash
>=4.4). It takes an environment file, and optionally a list of directories with
vagrant configurations. With a single parameter, it loops over all the
directories in alphabetical order, excluding those in the `experimental`
directory. Watch out for running VMs if you break the loop by hand.

After this, you will find up to 30GB of base images in `/var/lib/libvirt/images`,
which you need to remove by hand when you have finished testing or leave them
around for the next time.

You can give more memory or CPU juice to the VMs by editing [Vagrantfile.common](vagrant/Vagrantfile.common).

## Test Matrix

Tests fail with unsupported configurations or when the environment is not prepared correctly
due to missing setup/teardown parts in Ansible or functional tests. False positives
are also possible due to timing issues or flaky network connections.

If you have a result that deviates from the following matrix, that's probably a genuine bug or regression.
The data was created with crowdsec v1.4.1.

|                           | source/sqlite | pkg/sqlite | source/postgres | source/pgx | source/mysql (0) |
| ------------------------- | ------------- | ---------- | --------------- | ---------- | ---------------- |
| AmazonLinux 2             | ✓ (1)         | ✓ (1)      | old-db          | old-db     | wip              |
| CentOS 7                  | ✓             | ✓          | old-db          | old-db     | ✓                |
| CentOS 8                  | ✓             | ✓          | ✓               | ✓          | ✓                |
| CentOS 9                  | ✓             | ✓          | ✓               | ✓          | ✓                |
| Debian 9 (stretch)        | ✓             | ✓          | old-db          | old-db     | wip              |
| Debian 10 (buster)        | ✓             | ✓          | ✓               | ✓          | ✓                |
| Debian 11 (bullseye)      | ✓             | ✓          | ✓               | ✓          | ✓                |
| Debian (testing/bookworm) | ✓             | ✓          | ✓               | ✓          | wip              |
| Fedora 33                 | ✓             | ✓          | wip             | wip        | wip              |
| Fedora 34                 | ✓             | ✓          | ✓               | ✓          | wip              |
| Fedora 35                 | ✓             | ✓          | ✓               | ✓          | wip              |
| Fedora 36                 | ✓             | ✓          | ✓               | ✓          | wip              |
| FreeBSD 12                | ✓             | wip        | wip             | wip        | wip              |
| FreeBSD 13                | ✓             | wip        | wip             | wip        | wip              |
| Oracle 7                  | ✓             | ✓          | old-db          | old-db     | ✓                |
| Oracle 8                  | ✓             | ✓          | ✓               | ✓          | ✓                |
| Ubuntu 16.04 (xenial)     | ✓             | ✓          | old-db          | old-db     | ✓                |
| Ubuntu 18.04 (bionic)     | ✓             | ✓          | ✓               | ✓          | ✓                |
| Ubuntu 20.04 (focal)      | ✓             | ✓          | ✓               | ✓          | ✓                |
| Ubuntu 22.04 (jammy)      | ✓             | ✓          | ✓               | ✓          | ✓                |
|                           |               |            |                 |            |                  |

Note: all tests with `local/<database>` are expected to pass for `pkg/<database>` as well.

wip - missing ansible or bats parts, could be fixed in a future release

old-db - the database that ships with the distribution is not supported
(Postgres < 10). Won't fix, feel free to install the DB from an unofficial
repository.

0 - MySQL or MariaDB, depending on distribution defaults

1 - ansible may hang, passes all tests if run by hand
