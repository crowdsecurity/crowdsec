
# What is this?

This directory contains scripts for functional testing. The tests are run with
the [bats-core](https://github.com/bats-core/bats-core) framework, which is an
active fork of the older BATS (Bash Automated Testing System).

The goal is to be cross-platform but not explicitly test the packaging system
or service management. Those parts are specific to each distribution and are
tested separately (triggered by crowdsec releases, but they run in other
repositories).

### cscli

| Feature               | Covered            | Notes                      |
| :-------------------- | :----------------- | :------------------------- |
| `cscli alerts`        | -                  |                            |
| `cscli bouncers`      | `10_bouncers`      |                            |
| `cscli capi`          | `01_base`          | `status` only              |
| `cscli collections`   | `20_collections`   |                            |
| `cscli config`        | `01_base`          | minimal testing (no crash) |
| `cscli dashboard`     | -                  | docker inside docker 😞    |
| `cscli decisions`     | `9[78]_ipv[46]*`   |                            |
| `cscli hub`           | `dyn_bats/99_hub`  |                            |
| `cscli lapi`          | `01_base`          |                            |
| `cscli machines`      | `30_machines`      |                            |
| `cscli metrics`       | -                  |                            |
| `cscli parsers`       | -                  |                            |
| `cscli postoverflows` | -                  |                            |
| `cscli scenarios`     | -                  |                            |
| `cscli simulation`    | `50_simulation`    |                            |
| `cscli version`       | `01_base`          |                            |

### crowdsec

| Feature                        | Covered        | Notes                                      |
| :----------------------------- | :------------- | :----------------------------------------- |
| `systemctl` start/stop/restart | -              |                                            |
| agent behavior                 | `40_live-ban`  | minimal testing  (simple ssh-bf detection) |
| forensic mode                  | `40_cold-logs` | minimal testing (simple ssh-bf detection)  |
| starting without LAPI          | `02_nolapi`    |                                            |
| starting without agent         | `03_noagent`   |                                            |
| starting without CAPI          | `04_nocapi`    |                                            |
| prometheus testing             | -              |                                            |

### API

| Feature            | Covered          | Notes        |
| :----------------- | :--------------- | :----------- |
| alerts GET/POST    | `9[78]_ipv[46]*` |              |
| decisions GET/POST | `9[78]_ipv[46]*` |              |
| stream mode        | `99_lapi-stream-mode |          |



# How to use it

## pre-requisites

 - `git submodule init; git submodule update`
 - `daemonize (linux) or daemon (freebsd), bash, python3, openbsd-netcat`
 - `yq` from https://github.com/mikefarah/yq

## Running all tests

Run `make clean bats-all` to perform a test build + run.
To repeat test runs without rebuilding crowdsec, use `make bats-test`.


## Troubleshooting tests

See `./tests/run-tests` usage to run/debug single test.




# How does it work?

In BATS, you write tests in the form of Bash functions that have unique
descriptions (the name of the test). You can do most things that you can
normally do in a shell function. If there is any error condition, the test
fails. A set of functions is provided to implement assertions, and a mechanism
of `setup`/`teardown` is provided a the level of individual tests (functions)
or group of tests (files).

The stdout/stderr of the commands within the test function are captured by
bats-core and will only be shown if the test fails. If you want to always print
something to debug your test case, you can redirect the output to the file
descriptor 3:

```sh
@test "mytest" {
   echo "hello world!" >&3
   run some-command
   assert_success
   echo "goodbye." >&3
}
```

If you do that, please remove it once the test development is finished, because
this practice breaks the TAP protocol (unless each line has a '#' as first
character, but really, it's better to avoid unnecessary output when tests succeed).

You can find here the documentation for the main framework and the plugins we use in this test suite:

 - [bats-core tutorial](https://bats-core.readthedocs.io/en/stable/tutorial.html)
 - [Writing tests](https://bats-core.readthedocs.io/en/stable/writing-tests.html)
 - [bats-assert](https://github.com/bats-core/bats-assert)
 - [bats-support](https://github.com/bats-core/bats-support)
 - [bats-file](https://github.com/bats-core/bats-file)
 - [bats-mock](https://github.com/grayhemp/bats-mock)

> As it often happens with open source, the first results from search engines refer to the old, unmaintained forks.
> Be sure to use the links above to find the good versions.

Since bats-core is [TAP (Test Anything Protocol)](https://testanything.org/)
compliant, its output is in a standardized format. It can be integrated with a
separate [tap reporter](https://www.npmjs.com/package/tape#pretty-reporters) or
included in a larger test suite. The TAP specification is pretty minimalist and
some glue may be needed.


Other tools that you can find useful:

 - [mikefarah/yq](https://github.com/mikefarah/yq) - to parse and update YAML files on the fly
 - [aliou/bats.vim](https://github.com/aliou/bats.vim) - for syntax highlighting (use bash otherwise)

# setup and teardown

If you have read the bats-core tutorial linked above, you are aware of the
`setup` and `teardown` functions.

What you may have overlooked is that the script body outside the functions is
executed multiple times, so we have to be careful of what we put there.

Here we have a look at the execution flow with two tests:

```sh
echo "begin" >&3

setup_file() {
        echo "setup_file" >&3
}

teardown_file() {
        echo "teardown_file" >&3
}

setup() {
        echo "setup" >&3
}

teardown() {
        echo "teardown" >&3
}

@test "test 1" {
        echo "test #1" >&3
}

@test "test 2" {
        echo "test #2" >&3
}

echo "end" >&3
```

The above test suite produces the following output:

```
begin
end
setup_file
begin
end
 ✓ test 1
setup
test #1
teardown
begin
end
 ✓ test 2
setup
test #2
teardown
teardown_file
```

See how "begin" and "end" are repeated three times each? The code outside
setup/teardown/test functions is really executed three times (more as you add
more tests). You can put there variables or function definitions, but keep it
to a minimum and [don't write anything to the standard
output](https://bats-core.readthedocs.io/en/stable/writing-tests.html#code-outside-of-test-cases).
For most things you want to use `setup_file()` instead.

But.. there is a but. Quoting from [the FAQ](https://bats-core.readthedocs.io/en/stable/faq.html):

> You can simply source <your>.sh files. However, be aware that source`ing
> files with errors outside of any function (or inside `setup_file) will trip
> up bats and lead to hard to diagnose errors. Therefore, it is safest to only
> source inside setup or the test functions themselves.

This doesn't mean you can't do that, just that you're on your own if the is an error.


# Testing crowdsec

## Fixtures

For the purpose of functional tests, crowdsec and its companions (cscli, plugin
notifiers, bouncers) are installed in a local environment, which means tests
should not install or touch anything outside a `./tests/local` directory. This
includes binaries, configuration files, databases, data downloaded from
internet, logs... The use of `/tmp` is tolerated, but BATS also provides [three
useful
variables](https://bats-core.readthedocs.io/en/stable/writing-tests.html#special-variables):
`$BATS_SUITE_TMPDIR`, `$BATS_FILE_TMPDIR` and `$BATS_TEST_TMPDIR` that let you
ensure your desired level of isolation of temporary files across the tests.

When built with `make bats-build`, the binaries will look there by default for
their configuration and data needs. So you can run `./local/bin/cscli` from
a shell with no need for further parameters.

To set up the installation described above we provide a couple of scripts,
`instance-data` and `instance-crowdsec`. They manage fixture and background
processes; they are meant to be used in setup/teardown in several ways,
according to the specific needs of the group of tests in the file.

 - `instance-data make`

   Creates a tar file in `./local-init/init-config-data.tar`.
   The file contains all the configuration, hub and database files needed
   to restore crowdsec to a known initial state.
   Things like `machines add ...`, `capi register`, `hub update`, `collections
   install crowdsecurity/linux` are executed here so they don't need to be
   repeated for each test or group of tests.

 - `instance-data load`

   Extracts the files created by `instance-data make` for use by the local
   crowdsec instance. Crowdsec must not be running while this operation is
   performed.

 - `instance-crowdsec [ start | stop ]`

   Runs (or stops) crowdsec as a background process. PID and lockfiles are
   written in `./local/var/run/`.


Here are some ways to use these two scripts.

 - case 1: load a fresh crowsec instance + data for each test (01_base, 10_bouncers, 20_collections...)

    This offers the best isolation, but the tests run slower. More importantly,
    since there is no concept of "grouping" tests in bats-core with the exception
    of files, if you need to perform some setup that is common to two or more
    tests, you will have to repeat the code.

 - case 2: load a fresh set of data for each test, but run crowdsec only for
   the tests that need it, possibly after altering the configuration
   (02_nolapi, 03_noagent, 04_nocapi, 40_live-ban)

    This is useful because: 1) you sometimes don't want crowdsec to run at all,
    for example when testing `cscli` in isolation, or you may want to tweak the
    configuration inside the test function before running the lapi/agent. See
    how we use `yq` to change the YAML files to that effect.

 - case 3: start crowdsec with the initial set of configuration+data once, and keep it
   running for all the tests (50_simulation, 98_ipv4, 98_ipv6)

     This offers no isolation across tests, which over time could break more
     often as result, but you can rely on the test order to test more complex
     scenarios with a reasonable performance and the least amount of code.


## status, stdout and stderr

As we said, if any error occurs inside a test function, the test
fails immediately. You call `mycommand`, it exits with $? != 0, the test fails.

But how to test the output, then? If we call `run mycommand`, then $? will be 0
allowing the test to keep running. The real error status is stored in the
`$status` variable, and the command output and standard error content are put
together in the `$output` variable. By specifying `run --separate-stderr`, you
can have separated `$output` and `$stderr` variables.

The above is better explained in the bats-core tutorial. If you have not read it
yet, now is a good time.

The `$output` variable gets special treatment with the
[bats-support](https://github.com/bats-core/bats-support) and
[bats-assert][https://github.com/bats-core/bats-assert) plugins and can be
checked with `assert_*` commands. The `$stderr` variable does not have these,
but we can use `run echo "$stderr"` and then check `$output` with asserts.

Remember that `run` always overwrites the `$output` variable, so if you consume
it with `run jq <(output)` you can only do it once, because the second time it
will read the output of the `jq` command. But you can construct a list of all
the values you want and check them all in a single step.

Note that `<(output)` is substituted with the file name of a file descriptor,
so `mycmd <(output)` can become `mycmd /dev/fd/23`, `mycmd /tmp//sh-np.hpc7Zs`
or `mycmd /proc/self/fd/38` depending on the platform. To have it fed to
standard input, use `< <(output)`.

See the `lib/*.sh` and `bats/*.bats` files for other tricks we employ.

## file operations

We included the [bats-file](https://github.com/bats-core/bats-file) plugin to
check the result of file system operations: existence, type/size/ownership checks
on files, symlinks, directories, sockets.

## mocking external commands

The [bats-mock](https://github.com/grayhemp/bats-mock) plugin allows you to define
a "fake" behavior for the external commands called by a package under test, and
to record and assert which parameters are passed to it.

## gotchas

 - pay attention to tests that are not run - for example "bats warning: Executed 143
   instead of expected 144 tests". They are especially tricky to debug.

 - using the `load` command in `teardown()` causes tests to be silently skipped or break in "funny"
   ways. The other functions seem safe.

# Testing with MySQL and Postgres

By default, the tests are run with the embedded sqlite database engine. This should be
enough in most cases, since the database operations are abstracted via the `ent` ORM.

You can however easily test with a different engine.

## Postgres

Run Postgres somewhere, version 10 or above - easy to do in a docker container.

You also need to install a postgresql-client package or equivalent, to provide
recent pg_dump and pg_restore executables (not older than the PG version in the docker container).

```
$ sudo docker run --detach --name=postgres -p 5432:5432 --env="POSTGRES_PASSWORD=postgres" postgres:latest
```

The name of the container is not really important.
If you are not using Docker, you may need to adjust the `PGHOST`/`PGPORT`/`PGPASSWORD`/`PGUSER` variables
(defaults are 127.0.0.1, 5432, postgres, postgres).

An additional user and database both named `crowdsec_test` will be created.

Now you can build and run the tests (we skip bats-test-hub here, they really
should not be affected by a change in DB).

```
$ export DB_BACKEND=postgres
$ make clean bats-build bats-fixture bats-test
```

or with the pgx driver:

```
$ export DB_BACKEND=pgx
$ make clean bats-build bats-fixture bats-test
```

The value of DB_BACKEND must not change between the build/fixture/test steps.

## MySQL/MariaDB

Same considerations as above, with the following changes:

```
$ sudo docker run --cap-add=sys_nice --detach --name=mysql -p 3306:3306  --env="MYSQL_ROOT_PASSWORD=password" mysql
[...]
$ export DB_BACKEND=mysql
$ make clean bats-build bats-fixture bats-test
```

or for MariaDB

```
$ sudo docker run --cap-add=sys_nice --detach --name=mariadb -p 3306:3306  --env="MYSQL_ROOT_PASSWORD=password" mariadb
```

A mysql-client package is required as well.

## gotchas

 - Testing with Postgres or MySQL/MariaDB leads to (unpredictably) failing
   tests in the GitHub workflows, so we had to disable them by default. We do
   run these in a separate environment before doing releases.

