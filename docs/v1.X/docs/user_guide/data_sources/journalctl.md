# Journalctl Acquisition

This module allows `{{v1X.crowdsec.name}}` to acquire logs from journalctl files in one-shot and streaming mode.

## Configuration Parameters

 - journalctl_filters: A list of journalctl filters. This is mandatory.
 - source: Must be `journalctl`

Basic configuration example:
```yaml
source: journalctl
journalctl_filters:
 - _SYSTEMD_UNIT=ssh.service
```

## DSN and command-line

This module supports acquisition directly from the command line, to read journalctl logs in one shot.

A 'pseudo DSN' must be provided:

`crowdsec -type syslog -dsn journalctl://filters=_SYSTEMD_UNIT=ssh.service&filters=_UID=42`

You can specify the `log_level` parameter to change the log level for the acquisition :

`crowdsec -type syslog -dsn journalctl://filters=MY_FILTER&filters=MY_OTHER_FILTER&log_level=debug`
