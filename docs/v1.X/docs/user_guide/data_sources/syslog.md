# Syslog Acquisition

This module allows crowdsec to expose a syslog server, and ingest logs directly from another syslog server (or any software that knows how to forward logs with syslog).

Only UDP is supported.

Syslog messages must conform either to RFC3164 or RFC5424, and can be up to 2048 bytes long.


## Configuration Parameters

 - `listen_addr`: Address on which the syslog will listen. Defaults to 127.0.0.1.
 - `listen_port`: UDP port used by the syslog server. Defaults to 514.
 - `source`: Must be `syslog`

A basic configuration is as follows:

```yaml
source: syslog
listen_addr: 127.0.0.1
listen_port: 4242
labels:
 type: syslog
```

## DSN and command-line

This module does not support command-line acquisition.
