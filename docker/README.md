# Quick reference

* Documentation and help: https://docs.crowdsec.net/
* Crowdsec concepts: https://docs.crowdsec.net/docs/concepts
* Where to file issues: https://github.com/crowdsecurity/crowdsec

# What is Crowdsec

Crowdsec - An open-source, lightweight agent to detect and respond to bad behaviours. It also automatically benefits from our global community-wide IP reputation database.

# How to use this image

## Image flavors

All the following images are available on Docker Hub for the architectures
386, amd64, arm/v6, arm/v7, arm64.

### Alpine

 - `crowdsecurity/crowdsec:{version}`

Recommended for production usage. Also available on GitHub (ghrc.io).

 - `crowdsecurity/crowdsec:latest`

For development and testing.

since v1.4.2:

 - `crowdsecurity/crowdsec:slim`

Reduced size by 60%, does not include notifier plugins nor the GeoIP database.
If you need these details on decisions, running `cscli hub upgrade` inside the
container downloads the GeoIP database at runtime.


### Debian (since v1.3.3)

 - `crowdsecurity/crowdsec:{version}-debian`
 - `crowdsecurity/crowdsec:latest-debian`

The debian version includes support for systemd and journalctl.

### Custom

You can build your images with Dockerfile and Dockerfile-debian.

For example, if you want a Debian version without plugin notifiers:

```console
$ docker build -f Dockerfile.debian --build-arg=BUILD_ENV=slim
```

supported values for BUILD_ENV are: full, with-geoip, with-plugins, slim.


## Required configuration

### Journalctl (only for debian image)
To use journalctl as a log stream, with or without the `DSN` environment variable, it's important to mount the journal log from the host to the container itself.
This can be done by adding the following volume mount to the docker command:

```
-v /var/log/journal:/run/log/journal
```

### Logs ingestion and processing
Collections are a good place to start: https://docs.crowdsec.net/docs/collections/intro

Find collections, scenarios, parsers and postoverflows in the hub: https://hub.crowdsec.net


* Specify collections | scenarios | parsers | postoverflows to install via the environment variables (by default [`crowdsecurity/linux`](https://hub.crowdsec.net/author/crowdsecurity/collections/linux) is installed)
* Mount volumes to specify your log files that should be ingested by crowdsec
### Acquisition

`/etc/crowdsec/acquis.yaml` maps logs to the provided parsers. Find out more here: https://docs.crowdsec.net/docs/concepts/#acquisition

acquis.yaml example:
```shell
filenames:
 - /logs/auth.log
 - /logs/syslog
labels:
  type: syslog
---
filename: /logs/apache2/*.log
labels:
  type: apache2
```

`labels.type`: use `syslog` if the logs come from syslog, otherwise check the collection's documentation for the relevant type.

## Recommended configuration
### Volumes

We strongly suggest mounting **named volumes** for Crowdsec configuration and database to avoid credentials and decisions loss in case of container destruction and recreation, version update, etc.

* Credentials and configuration: `/etc/crowdsec`
* Database when using SQLite (default): `/var/lib/crowdsec/data`

## Start a Crowdsec instance

```shell
docker run -d \
    -v local_path_to_crowdsec_config/acquis.yaml:/etc/crowdsec/acquis.yaml \
    -v crowdsec_config:/etc/crowdsec \
    -v crowdsec_data:/var/lib/crowdsec/data \
    -v /var/log/auth.log:/logs/auth.log:ro \
    -v /var/log/syslog.log:/logs/syslog.log:ro \
    -v /var/log/apache:/logs/apache:ro \
    -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/sshd" \
    -p 8080:8080 -p 6060:6060 \
    --name crowdsec crowdsecurity/crowdsec
```

## ... or docker-compose

Check this full-stack example using docker-compose: https://github.com/crowdsecurity/example-docker-compose

# How to extend this image

## Full configuration
The container is built with a specific docker
[configuration](https://github.com/crowdsecurity/crowdsec/blob/master/docker/config.yaml).
If you need to change it and the docker variables (see below) are not enough,
you can bind `/etc/crowdsec/config.yaml` to your a configuration file.

## Notifications
If you wish to use the [notification system](https://docs.crowdsec.net/docs/notification_plugins/intro), you will need to mount at least a custom `profiles.yaml` and a notification configuration to `/etc/crowdsec/notifications`

# Deployment use cases
Crowdsec is composed of an `agent` that parses logs and creates `alerts`, and a
`local API (LAPI)` that transforms these alerts into decisions. Both functions
are provided by the same executables, so the agent and the LAPI can run in the
same or separate containers. In complex configurations, it makes sense to have
agents on each machine that runs the protected applications, and a LAPI that
gathers all signals from agents and communicates with the `central API`.

## Register a new agent with LAPI
```shell
docker exec -it crowdsec_lapi_container_name cscli machines add agent_user_name --password agent_password
```

## Run an agent connected to LAPI

Add the following environment variables to the docker run command:

* `DISABLE_LOCAL_API=true`
* `AGENT_USERNAME="agent_user_name"` - agent_user_name previously registered with LAPI
* `AGENT_PASSWORD="agent_password"` - agent_password previously registered with LAPI
* `LOCAL_API_URL="http://LAPI_host:LAPI_port"`

# Next steps

## Bouncers

Crowdsec being a detection component, the remediation is implemented using `bouncers`. Each bouncer protects a specific component. Find out more:

https://hub.crowdsec.net/browse/#bouncers

https://docs.crowdsec.net/docs/user_guides/bouncers_configuration/

### Automatic Bouncer Registration

You can automatically register bouncers with the crowdsec container at startup, using environment variables or Docker secrets. You cannot use this process to update an existing bouncer without first deleting it.

To use environment variables, they should be in the format `BOUNCER_KEY_<name>=<key>`. e.g. `BOUNCER_KEY_nginx=mysecretkey12345`.

To use Docker secrets, the secret should be named `bouncer_key_<name>` with a content of `<key>`. e.g. `bouncer_key_nginx` with content `mysecretkey12345`.

A bouncer key can be any string but we recommend an alphanumeric value for consistency with crowdsec-generated keys and avoid problems with escaping special characters.

## Console
We provide a web-based interface to get more from Crowdsec: https://docs.crowdsec.net/docs/console

Subscribe here: https://app.crowdsec.net

# Caveats

Using binds rather than named volumes ([complete explanation here](https://docs.docker.com/storage/volumes/)) results in more complexity as you'll have to bind the relevant files one by one whereas with named volumes you can mount full configuration and data folders. On the other hand, named volumes are less straightforward to navigate.

# Reference
## Environment Variables

| Variable                | Default                   | Description |
| ----------------------- | ------------------------- | ----------- |
| `CONFIG_FILE`           | `/etc/crowdsec/config.yaml` | Configuration file location |
| `DSN`                   | | Process a single source in time-machine: `-e DSN="file:///var/log/toto.log"` or `-e DSN="cloudwatch:///your/group/path:stream_name?profile=dev&backlog=16h"` or `-e DSN="journalctl://filters=_SYSTEMD_UNIT=ssh.service"` |
| `TYPE`                  | | [`Labels.type`](https://docs.crowdsec.net/Crowdsec/v1/references/acquisition/) for file in time-machine: `-e TYPE="<type>"` |
| `TEST_MODE`             | false | Don't run the service, only test the configuration: `-e TEST_MODE=true` |
| `TZ`                    | | Set the [timezone](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) to ensure the logs have a local timestamp. |
| `LOCAL_API_URL`         | `http://0.0.0.0:8080` | The LAPI URL, you need to change this when `DISABLE_LOCAL_API` is true: `-e LOCAL_API_URL="http://lapi-address:8080"` |
| `DISABLE_AGENT`         | false | Disable the agent, run a LAPI-only container |
| `DISABLE_LOCAL_API`     | false | Disable LAPI, run an agent-only container |
| `DISABLE_ONLINE_API`    | false | Disable online API registration for signal sharing |
| `CUSTOM_HOSTNAME`       | localhost | Custom hostname for LAPI registration (with agent and LAPI on the same container) |
| `PLUGIN_DIR`            | `/usr/local/lib/crowdsec/plugins/` | Directory for plugins: `-e PLUGIN_DIR="<path>"` |
| `BOUNCER_KEY_<name>`    | | Register a bouncer with the name `<name>` and a key equal to the value of the environment variable. |
| `METRICS_PORT`          | 6060 | Port to expose Prometheus metrics |
|                         | | |
| __Console__             | | |
| `ENROLL_KEY`            | | Enroll key retrieved from [the console](https://app.crowdsec.net/) to enroll the instance. |
| `ENROLL_INSTANCE_NAME`  | | To set an instance name and see it on [the console](https://app.crowdsec.net/) |
| `ENROLL_TAGS`           | | Tags of the enrolled instance, for search and filter |
|                         | | |
| __Password Auth__       | | |
| `AGENT_USERNAME`        | | Agent username (to register if is LAPI or to use if it's an agent): `-e AGENT_USERNAME="machine_id"` |
| `AGENT_PASSWORD`        | | Agent password (to register if is LAPI or to use if it's an agent): `-e AGENT_PASSWORD="machine_password"` |
|                         | | |
| __TLS Auth/encryption   | | |
| `USE_TLS`               | false | Enable TLS on the LAPI |
| `CERT_FILE`             | /etc/ssl/cert.pem | TLS Certificate path |
| `KEY_FILE`              | /etc/ssl/key.pem | TLS Key path |
| `CA_CERT_PATH`          | | CA file |
| `AGENTS_ALLOWED_OU`     | agent-ou | OU values allowed for agents, separated by comma |
| `BOUNCERS_ALLOWED_OU`   | bouncer-ou | OU values allowed for bouncers, separated by comma |
|                         | | |
| __Hub management__      | | |
| `COLLECTIONS`           | | Collections to install, separated by space: `-e COLLECTIONS="crowdsecurity/linux crowdsecurity/apache2"` |
| `SCENARIOS`             | | Scenarios to install, separated by space |
| `PARSERS`               | | Parsers to install, separated by space |
| `POSTOVERFLOWS`         | | Postoverflows to install, separated by space |
| `DISABLE_COLLECTIONS`   | | Collections to remove, separated by space: `-e DISABLE_COLLECTIONS="crowdsecurity/linux crowdsecurity/nginx"` |
| `DISABLE_PARSERS`       | | Parsers to remove, separated by space |
| `DISABLE_SCENARIOS`     | | Scenarios to remove, separated by space |
| `DISABLE_POSTOVERFLOWS` | | Postoverflows to remove, separated by space |
|                         | | |
| __Log verbosity__       | | |
| `LEVEL_INFO`            | false | Force INFO level for the container log |
| `LEVEL_DEBUG`           | false | Force DEBUG level for the container log |
| `LEVEL_TRACE`           | false | Force TRACE level (VERY verbose) for the container log |

## Volumes

* `/var/lib/crowdsec/data/` - Directory where all crowdsec data (Databases) is located

* `/etc/crowdsec/` - Directory where all crowdsec configurations are located

## File Locations

* `/usr/local/bin/crowdsec` - Crowdsec binary

* `/usr/local/bin/cscli` - Crowdsec CLI binary to interact with crowdsec

# Find Us

* [GitHub](https://github.com/crowdsecurity/crowdsec)

# Contributing

Please read [contributing](https://docs.crowdsec.net/Crowdsec/v1/contributing/) for details on our code of conduct, and the process for submitting pull requests to us.

# License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE) file for details.
