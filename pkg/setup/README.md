
> **_NOTE_**: The following document describes an experimental, work-in-progress feature. To enable the `cscli setup` command, set the environment variable `CROWDSEC_FEATURE_CSCLI_SETUP=true` or add the line " - cscli_setup" to `/etc/crowdsec/feature.yaml`. Any feedback is welcome.

---

# cscli setup

The "cscli setup" command can configure a crowdsec instance based on the services that are installed or running on the server.

There are three main subcommands:

- `cscli setup detect`: *detect* the services, the OS family, version or the Linux distribution
- `cscli setup install-hub`: *install* the recommended collections, parsers, etc. based on the detection result
- `cscli setup datasources`: *generate* the appropriate acquisition rules

The setup command is used in the `wizard.sh` script, but can also be invoked by hand or customized via a configuration file
by adding new services, log locations and detection rules.

Detection and installation are performed as separate steps, as you can see in the following diagram:

```
 +-------------+
 |             |
 | detect.yaml |
 |             |
 +-------------+
        |
        v
  setup detect
        |
        v
 +--------------+
 |              +---> setup install-hub     +-----------------------+
 |  setup.yaml  |                           |                       |
 |              +---> setup datasources --->| etc/crowdsec/acquis.d |
 +--------------+                           |                       |
                                            +-----------------------+
```

You can inspect and customize the intermediary file (`setup.yaml`), which is useful
in case of many instances, deployment automation or unusual setups.

A subcommand can be used to check your changes in this case:

- `cscli setup validate`: *validate* or report errors on a setup file

## Basic usage

Identify the existing services and write out what was detected:

```console
# cscli setup detect > setup.yaml
```

See what was found.

```console
# cscli setup install-hub setup.yaml --dry-run
dry-run: would install collection crowdsecurity/apache2
dry-run: would install collection crowdsecurity/linux
dry-run: would install collection crowdsecurity/pgsql
dry-run: would install parser crowdsecurity/whitelists
```

Install the objects (parsers, scenarios...) required to support the detected services:

```console
# cscli setup install-hub setup.yaml
INFO[29-06-2022 03:16:14 PM] crowdsecurity/apache2-logs : OK              
INFO[29-06-2022 03:16:14 PM] Enabled parsers : crowdsecurity/apache2-logs 
INFO[29-06-2022 03:16:14 PM] crowdsecurity/http-logs : OK             
[...]
INFO[29-06-2022 03:16:18 PM] Enabled crowdsecurity/linux      
```

Generate the datasource configuration:

```console
# cscli setup datasources setup.yaml --to-dir /etc/crowdsec/acquis.d
```

With the above command, each detected service gets a corresponding file in the
`acquis.d` directory. Running `cscli setup` again may add more services as they
are detected, but datasource files or hub items are never removed
automatically.


## The detect.yaml file

A detect.yaml file is downloaded when you first install crowdsec, and is updated by the `cscli hub update`
command.

> **_NOTE_**: XXX XXX - this is currently not the case, the file is distributed in the crowdsec repository, but it should change.

You can see the default location with `cscli setup detect --help | grep detect-config`

The YAML file contains a version number (always 1.0) and a list of sections, one per supported service.

Each service defines its detection rules, the recommended hub items and
recommended datasources. The same software can be defined in multiple service
sections: for example, apache on debian and fedora have different detection
rules and different datasources so it requires two sections to support both platforms.

The following are minimal `detect.yaml` examples just to show a few concepts.

```yaml
version: 1.0

services:

  apache2:
    when:
      - ProcessRunning("apache2")
    install:
      collections:
        - crowdsecurity/apache2
    datasources:
      source: file
      labels:
        type: apache2
      filenames:
        - /var/log/apache2/*.log
        - /var/log/httpd/*.log
```


- `ProcessRunning()` matches the process name of a running application. The
`when:` clause can contain any number of expressions, they are all evaluated
and must all return true for a service to be detected (implied *and* clause, no
short-circuit). A missing or empty `when:` section is evaluated as true.
The [expression
engine](https://github.com/antonmedv/expr/blob/master/docs/Language-Definition.md)
is the same one used by CrowdSec parser filters. You can force the detection of
a process by using the `cscli setup detect... --force-process <processname>`
flag. It will always behave as if `<processname>` was running.

The `install:` section can contain any number of collections, parsers, scenarios
and postoverflows. In practices, it's most often a single collection.

The `datasource:` section is copied as-is in the acquisition file.

> **_NOTE_**: XXX TODO - the current version does not validate the `datasource:` mapping. Bad content is written to acquis.d until crowdsec chokes on it.

Detecting a running process may seem a good idea, but if a process manager like
systemd is available it's better to ask it for the information we want.


```yaml
version: 1.0

services:

  apache2-systemd:
    when:
      - UnitFound("apache2.service")
      - OS.ID != "centos"
    install:
      collections:
        - crowdsecurity/apache2
    datasource:
      source: file
      labels:
        type: syslog
      filenames:
        - /var/log/apache2/*.log

  apache2-systemd-centos:
    when:
      - UnitFound("httpd.service")
      - OS.ID == "centos"
    install:
      collections:
        - crowdsecurity/apache2
    datasource:
      source: file
      labels:
        type: syslog
      filenames:
        - /var/log/httpd/*.log
```

Here we see two more detection methods:

- `UnitFound()` matches the name of systemd units, if the are in state enabled,
  generated or static. You can see here that CentOS is using a different unit
  name for Apache so it must have its own service section. You can force the
  detection of a unit by using the `cscli setup detect... --force-unit <unitname>` flag.

- OS.Family, OS.ID and OS.RawVersion are read from /etc/os-release in case of
  Linux, and detected by other methods for FreeBSD and Windows. Under FreeBSD
  and Windows, the value of OS.ID is the same as OS.Family. If OS detection
  fails, it can be overridden with the flags `--force-os-family`, `--force-os-id`
  and `--force-os-version`.

If you want to ignore one or more services (i.e. not install anything and not
generate acquisition rules) you can specify it with `cscli setup detect...
--skip-service <servicename>`. For example, `--skip-service apache2-systemd`.
If you want to disable systemd unit detection, use `cscli setup detect... --snub-systemd`.

If you used the `--force-process` or `--force-unit` flags, but none of the
defined services is looking for them, you'll have an error like "detecting
services: process(es) forced but not supported".

> **_NOTE_**: XXX XXX - having an error for this is maybe too much, but can tell that a configuration is outdated. Could this be a warning with optional flag to make it an error?

We used the `OS.ID` value to check for the linux distribution, but since the same configuration
is required for CentOS and the other RedHat derivatives, it's better to check for the existence
of a file that is known to exist in all of them:

```yaml
version: 1.0

services:

  apache2-systemd-deb:
    when:
      - UnitFound("apache2.service")
      - PathExists("/etc/debian_version")
    install:
    # [...]

  apache2-systemd-rpm:
    when:
      - UnitFound("httpd.service")
      - PathExists("/etc/redhat-release")
    install:
    # [...]
```

- `PathExists()` evaluates to true if a file, directory or link exists at the
  given path. It does not check for broken links.



Rules can be used to detect operating systems and environments:

```yaml
version: 1.0

services:

  linux:
    when:
      - OS.Family == "linux"
    install:
      collections:
        - crowdsecurity/linux
    datasource:
      type: file
      labels:
        type: syslog
      log_files:
      - /var/log/syslog
      - /var/log/kern.log
      - /var/log/messages

  freebsd:
    when:
      - OS.Family == "freebsd"
    install:
      collections:
        - crowdsecurity/freebsd

  windows:
    when:
      - OS.Family == "windows"
    install:
      collections:
        - crowdsecurity/windows
```

The OS object contains a methods to check for version numbers:
`OS.VersionCheck("<constraint>")`. It uses the
[Masterminds/semver](https://github.com/Masterminds/semver) package and accepts
a variety of operators.

Instead of: OS.RawVersion == "1.2.3" you should use `OS.VersionCheck("~1")`,
`OS.VersionCheck("~1.2")` depending if you want to match the major or the minor
version. It's unlikely that you need to match the exact patch level.

Leading zeroes are permitted, to allow comparison of Ubuntu versions: strict semver rules would treat "22.04" as invalid.


# The `setup.yaml` file

This file does not actually have a specific name, as it's usually written to standard output.

For example, on a Debian system running Apache under systemd you can execute:

```console
$ cscli setup detect --yaml
setup:
  - detected_service: apache2-systemd-deb
    install:
      collections:
        - crowdsecurity/apache2
    datasource:
      filenames:
        - /var/log/apache2/*.log
      labels:
        type: apache2
  - detected_service: linux
    install:
      collections:
        - crowdsecurity/linux
    datasource:
      filenames:
        - /var/log/syslog
        - /var/log/kern.log
        - /var/log/messages
      labels:
        type: syslog
  - detected_service: whitelists
    install:
      parsers:
        - crowdsecurity/whitelists
```

The default output format is JSON, which is compatible with YAML but less readable to humans.

 - `detected_service`: used to generate a name for the files written to `acquis.d`
 - `install`: can contain collections, parsers, scenarios, postoverflows
 - `datasource`: copied to `acquis.d`


```console
$ cscli setup datasources --help
generate datasource (acquisition) configuration from a setup file

Usage:
  cscli setup datasources [setup_file] [flags]

Flags:
  -h, --help            help for datasources
      --to-dir string   write the configuration to a directory, in multiple files
[...]
```

If the `--to-dir` option is not specified, a single monolithic `acquis.yaml` is printed to the standard output.

