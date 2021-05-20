# Cloudwatch acquisition

This module allows `{{v1X.crowdsec.name}}` to acquire logs from AWS's cloudwatch service, in one-shot and streaming mode.

# Configuration

To monitor a given stream within a group :

```yaml
source: cloudwatch
group_name: /aws/my/group/
stream_name: 'given_stream'
aws_profile: monitoring
aws_config_dir: /home/user/.aws/
labels:
  type: apigateway
```

To monitor streams matching regexp within a group :

```yaml
source: cloudwatch
group_name: /aws/my/group/
stream_regexp: '^stream[0-9]+$'
aws_profile: monitoring
labels:
  type: apigateway
```

Look at the `configuration parameters` to view all supported options.

## Configuration parameters


### group_name

Name of the group to monitor, exact match.

### stream_regexp

A RE2 expression that will restrict streams within the group that will be monitored.

### stream_name

Name of stream to monitor, exact match.

### *_limit

 - describelogstreams_limit : control the pagination size of describelogstreams calls (default: `1000`)
 - getlogeventspages_limit : control the pagination size of getlogeventspages calls (default: `1000`)

### *_interval

> note : AWS SDK allows to identify streams according to the timestamp of the latest even within, and this is what we rely on.

 - poll_new_stream_interval : frequency to poll for new stream within given group (default `10s`)
 - max_stream_age : open only streams for which last event is at most this age (default `5m`)
 - poll_stream_interval : frequency to poll for new events within given group (default `10s`)
 - stream_read_timeout : stop reading a given stream when no new events have been seen for this duration (default `10m`)

### prepend_cloudwatch_timestamp

When set to `true` (default: `false`), prepend the cloudwatch event timestamp to the generated log string. This is intended for cases where you log itself wouldn't contain timestamp.

### aws_profile

The aws profile to use to poll cloudwatch, relies on your `~/.aws/config/`.

### aws_config_dir

The path to your `~/.aws/`, defaults to `/root/.aws`.

# DSN and command-line

cloudwatch implements a very approximative DSN, as follows : `cloudwatch:///your/group/path:stream_name?[args]`

Supported args are :

  - `log_level` : set log level of parser
  - `profile` : set aws profile name
  - `start_date` / `end_date` : provide start and end date limits for events, see [supported formats](https://hub.crowdsec.net/author/crowdsecurity/configurations/dateparse-enrich)
  - `backlog` : provide a duration, events from now()-duration till now() will be read

# Notes

This data source lacks unit tests because mocking aws sdk is fastidious.





