# Quick reference

* Documentation and help: https://docs.crowdsec.net/
* Crowdsec concepts: https://docs.crowdsec.net/docs/concepts
* Where to file issues: https://github.com/crowdsecurity/crowdsec


# What is Crowdsec

Crowdsec - An open-source, lightweight agent to detect and respond to bad behaviours. It also automatically benefits from our global community-wide IP reputation database.

# How to use this image

## Required configuration

### Logs ingestion and processing
Collections are a good place to start: https://docs.crowdsec.net/docs/collections/intro

Find collections|scenarios|parsers|postoverflows in the hub: https://hub.crowdsec.net


* Specify collections|scenarios|parsers/postoverflows to install via the environment variables (by default [`crowdsecurity/linux`](https://hub.crowdsec.net/author/crowdsecurity/collections/linux) is installed)
* Mount volumes to specify your log files that should be ingested by crowdsec
### Acquisition

`/etc/crowdsec/acquis.yaml` maps logs to provided parsers. Find out more here: https://docs.crowdsec.net/docs/concepts/#acquisition

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

`labels.type`: use `syslog` if logs origin is `syslog`, checkout collection's documentation for the relevant type otherwise.

## Recommended configuration
### Volumes

We strongly suggest to mount **named volumes** for Crowdsec configuration and database to avoid credentials and decisions loss in case of container's destruction and recreation, version update, etc.
* Credentials and configuration: `/etc/crowdsec`
* Database when using default SQLite: `/var/lib/crowdsec/data`

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

Check this full stack example using docker-compose: https://github.com/crowdsecurity/example-docker-compose
# How to extend this image
## Full configuration
The container is built with specific docker [configuration](https://github.com/crowdsecurity/crowdsec/blob/master/docker/config.yaml). If you need to change it, bind `/etc/crowdsec/config.yaml` to your local configuration file
## Notifications
If you wish to use the [notification system](https://docs.crowdsec.net/docs/notification_plugins/intro), you will need to mount at least a custom `profiles.yaml` and a notification configuration to `/etc/crowdsec/notifications`

# Deployment use cases
Crowdsec is composed of an `agent` that parse logs and creates `alerts` that `local API` or `LAPI` tranform into decisions. Both can run in the same process but also on separated containers as it makes sense in complex configurations to have agents on the same machines as the protected component and a LAPI that gather all signals from agents and communicate with the `central api`.

## Register a new agent with LAPI
```shell
docker exec -it crowdsec_lapi_container_name cscli machines add agent_user_name --password agent_password
```

## Run an agent connected to LAPI
Add following environment variables to your docker run command:
* `DISABLE_LOCAL_API=true`
* `AGENT_USERNAME="agent_user_name"` - agent_user_name previously registred with LAPI
* `AGENT_PASSWORD="agent_password"` - agent_password previously registered with LAPI
* `LOCAL_API_URL="http://LAPI_host:LAPI_port"`

# Next steps
## Bouncers
Crowdsec being a detection component, remediation is implemented using `bouncers`. Each bouncer protect a specific component. Find out more:

https://hub.crowdsec.net/browse/#bouncers

https://docs.crowdsec.net/docs/user_guides/bouncers_configuration/

## Console
We provide a web based interface to get more from Crowdsec: https://docs.crowdsec.net/docs/console

Subscribe here: https://app.crowdsec.net

# Caveats
Using binds rather than named volumes ([more explanation here](https://docs.docker.com/storage/volumes/)) results in more complexity as you'll have to bind relevant files one by one where with named volumes you can mount full configuration and data folders. On the other hand, named volumes are less straightforward to navigate.

# Reference
## Environment Variables

* `COLLECTIONS`             - Collections to install from the [hub](https://hub.crowdsec.net/browse/#collections), separated by space : `-e COLLECTIONS="crowdsecurity/linux crowdsecurity/apache2"`
* `SCENARIOS`               - Scenarios to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e SCENARIOS="crowdsecurity/http-bad-user-agent crowdsecurity/http-xss-probing"`
* `PARSERS`                 - Parsers to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e PARSERS="crowdsecurity/http-logs crowdsecurity/modsecurity"`
* `POSTOVERFLOWS`           - Postoverflows to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e POSTOVERFLOWS="crowdsecurity/cdn-whitelist"`
* `CONFIG_FILE`             - Configuration file (default: `/etc/crowdsec/config.yaml`) : `-e CONFIG_FILE="<config_path>"`
* `DSN`                     - Process a single source in time-machine : `-e DSN="file:///var/log/toto.log"` or `-e DSN="cloudwatch:///your/group/path:stream_name?profile=dev&backlog=16h"` or `-e DSN="journalctl://filters=_SYSTEMD_UNIT=ssh.service"`
* `TYPE`                    - [`Labels.type`](https://docs.crowdsec.net/Crowdsec/v1/references/acquisition/) for file in time-machine : `-e TYPE="<type>"`
* `TEST_MODE`               - Only test configs (default: `false`) : `-e TEST_MODE="<true|false>"`
* `TZ`                      - Set the [timezone](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) to ensure logs have a local timestamp.
* `DISABLE_AGENT`           - Only test configs (default: `false`) : `-e DISABLE_AGENT="<true|false>"`
* `DISABLE_LOCAL_API`       - Disable local API (default: `false`) : `-e DISABLE_LOCAL_API="<true|false>"`
* `AGENT_USERNAME`          - Agent username (to register if is LAPI or to use if it's an agent) : `-e AGENT_USERNAME="machine_id"`
* `AGENT_PASSWORD`          - Agent password (to register if is LAPI or to use if it's an agent) : `-e AGENT_PASSWORD="machine_password"`
* `LOCAL_API_URL`           - To specify when an agent needs to connect to a LAPI crowdsec (To use only when `DISABLE_LOCAL_API` is set to `true`) : `-e LOCAL_API_URL="http://lapi-address:8080"`
* `DISABLE_ONLINE_API`      - Disable Online API registration for signal sharing (default: `false`) : `-e DISABLE_ONLINE_API="<true|false>"`
* `LEVEL_TRACE`             - Trace-level (VERY verbose) on stdout (default: `false`) : `-e LEVEL_TRACE="<true|false>"`
* `LEVEL_DEBUG`             - Debug-level on stdout (default: `false`) : `-e LEVEL_DEBUG="<true|false>"`
* `LEVEL_INFO`              - Info-level on stdout (default: `false`) : `-e LEVEL_INFO="<true|false>"`

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
