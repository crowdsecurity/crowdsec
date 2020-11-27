# Crowdsec

Crowdsec - An open-source, lightweight agent to detect and respond to bad behaviours. It also automatically benefits from our global community-wide IP reputation database.

## Getting Started

Before starting using docker image, we suggest you to read our documentation to understand all [crowdsec concepts](https://docs.crowdsec.net/).

### Prerequisities


In order to run this container you'll need docker installed.

* [Windows](https://docs.docker.com/windows/started)
* [OS X](https://docs.docker.com/mac/started/)
* [Linux](https://docs.docker.com/linux/started/)

### How to use ?

#### Build

```shell
git clone https://github.com/crowdsecurity/crowdsec.git && cd crowdsec
docker build -t crowdsec .
```

#### Run

The container is built with specific docker [configuration](https://github.com/crowdsecurity/crowdsec/blob/master/docker/config.yaml) :

You should apply following configuration before starting it :

* Specify collections|scenarios|parsers/postoverflows to install via the environment variables (by default [`crowdsecurity/linux`](https://hub.crowdsec.net/author/crowdsecurity/collections/linux) is installed)
* Mount volumes to specify your configuration
* Mount volumes to specify your log files that should be ingested by crowdsec (set up in acquis.yaml)
* Mount other volumes : if you want to share the database for example

```shell
docker run -d -v config.yaml:/etc/crowdsec/config.yaml \
    -v acquis.yaml:/etc/crowdsec/acquis.yaml \
    -e COLLECTIONS="crowdsecurity/sshd"
    -v /var/log/auth.log:/var/log/auth.log \
    -v /path/mycustom.log:/var/log/mycustom.log \
    --name crowdsec <built-image-tag>
```

#### Example

I have my own configuration :
```shell
user@cs ~/crowdsec/config $ ls
acquis.yaml  config.yaml
```

Here is my acquis.yaml file:
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

So, I want to run crowdsec with :

* My configuration files
* Ingested my path logs specified in acquis.yaml
* Share the crowdsec sqlite database with my host (You need to create empty file first, otherwise docker will create a directory instead of simple file)
* Expose local API through host (listen by default on `8080`)
* Expose prometheus handler through host (listen by default on `6060`)

```shell
touch /path/myDatabase.db
docker run -d -v config.yaml:/etc/crowdsec/config.yaml \
    -v acquis.yaml:/etc/crowdsec/acquis.yaml \
    -v /var/log/auth.log:/logs/auth.log \
    -v /var/log/syslog.log:/logs/syslog.log \
    -v /var/log/apache:/logs/apache \
    -v /path/myDatabase.db:/var/lib/crowdsec/data/crowdsec.db \
    -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/sshd" \
    -p 8080:8080 -p 6060:6060 \
    --name crowdsec <built-image-tag>
```

### Environment Variables

* `COLLECTIONS`             - Collections to install from the [hub](https://hub.crowdsec.net/browse/#collections), separated by space : `-e COLLECTIONS="crowdsecurity/linux crowdsecurity/apache2"`
* `SCENARIOS`               - Scenarios to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e SCENARIOS="crowdsecurity/http-bad-user-agent crowdsecurity/http-xss-probing"`
* `PARSERS`                 - Parsers to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e PARSERS="crowdsecurity/http-logs crowdsecurity/modsecurity"`
* `POSTOVERFLOWS`           - Postoverflows to install from the [hub](https://hub.crowdsec.net/browse/#configurations), separated by space : `-e POSTOVERFLOWS="crowdsecurity/cdn-whitelist"`
* `CONFIG_FILE`             - Configuration file (default: `/etc/crowdsec/config.yaml`) : `-e CONFIG_FILE="<config_path>"`
* `FILE_PATH`               - Process a single file in time-machine : `-e FILE_PATH="<file_path>"`
* `JOURNALCTL_FILTER`       - Process a single journalctl output in time-machine : `-e JOURNALCTL_FILTER="<journalctl_filter>"`
* `TYPE`                    - [`Labels.type`](https://https://docs.crowdsec.net/Crowdsec/v1/references/acquisition/) for file in time-machine : `-e TYPE="<type>"`
* `TEST_MODE`               - Only test configs (default: `false`) : `-e TEST_MODE="<true|false>"`
* `DISABLE_AGENT`           - Only test configs (default: `false`) : `-e DISABLE_AGENT="<true|false>"`
* `DISABLE_LOCAL_API`       - Disable local API (default: `false`) : `-e DISABLE_API="<true|false>"`
* `REGISTER_TO_ONLINE_API`  - Register to Online API (default: `false`) : `-e REGISTER_TO_ONLINE_API="<true|false>"`
* `LEVEL_TRACE`             - Trace-level (VERY verbose) on stdout (default: `false`) : `-e LEVEL_TRACE="<true|false>"`
* `LEVEL_DEBUG`             - Debug-level on stdout (default: `false`) : `-e LEVEL_DEBUG="<true|false>"`
* `LEVEL_INFO`              - Info-level on stdout (default: `false`) : `-e LEVEL_INFO="<true|false>"`

### Volumes

* `/var/lib/crowdsec/data/` - Directory where all crowdsec data (Databases) is located

* `/etc/crowdsec/` - Directory where all crowdsec configurations are located

#### Useful File Locations

* `/usr/local/bin/crowdsec` - Crowdsec binary
  
* `/usr/local/bin/cscli` - Crowdsec CLI binary to interact with crowdsec

## Find Us

* [GitHub](https://github.com/crowdsecurity/crowdsec)

## Contributing

Please read [contributing](https://docs.crowdsec.net/Crowdsec/v1/contributing/) for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE) file for details.