# Overview

The Winlog package is a native Go Windows Event Log API. Supported features
include full reading, filtering and rendering of event logs on Windows from a go
binary.

## Features

* **Reading Event Logs** - Event logs are read using native Microsoft syscalls
for log reading that is quick and requires minimal resources.

* **Filtering Event Logs** - Event logs that are read can be tailored using
standard XML filtering strings.

* **Rendering Event Logs** - If the full text of an event log is desired, it can
be rendered in its entirety for use elsewhere.

## Requirements

Any version of Windows 10 and Windows Server 2012 R2 and up are compatible with
this library.

## How to use this library

See the examples folder for additional help and examples demonstrating the use
of this library.

## Contact

We have a public discussion list at
[google-winops@googlegroups.com](https://groups.google.com/forum/#!forum/google-winops)

## Disclaimer

This is not an official Google product.


