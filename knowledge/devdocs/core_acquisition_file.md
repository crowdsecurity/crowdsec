# File acquisition

## Language

**Tail mode**:
YAML field on the file datasource selecting how log files are read in live (`mode: tail`) acquisition. Values: `default` (empty or absent maps here) keeps the file handle open between reads; `stat` opens, reads new bytes, and closes the handle on each poll cycle.
_Avoid_: tail implementation, tailer mode

**Stat poll interval**:
YAML duration (`stat_poll_interval`) controlling how often the file module polls when `tail_mode: stat`. Default 1s when unset or zero; `-1` disables automatic polling (tests drive reads manually). Ignored when `tail_mode` is `default`.
_Avoid_: poll interval

## Overview

The file acquisition module reads log files from configured paths and emits `pipeline.Event` lines. Live mode implements `RestartableStreamer.Stream(ctx, out)` with context-aware shutdown.

## How to use

- Configure live tailing in acquis YAML with `mode: tail` and `filenames` globs.
- Omit `tail_mode` or set `tail_mode: default` for long-lived handle behaviour on local disks.
- Set `tail_mode: stat` with optional `stat_poll_interval` on network shares where open handles cause pressure (for example Azure SMB).
- Pass a cancellable context to `Stream`; cancel it to stop tailing and release file handles before teardown.

## Key files

- `pkg/acquisition/modules/file/config.go` — YAML validation for `tail_mode` and `stat_poll_interval`
- `pkg/acquisition/modules/file/run.go` — `Stream`, `setupTailForFile`, tailwrapper wiring
- `pkg/acquisition/modules/file/init.go` — `RestartableStreamer` interface compliance

## Gotchas

- Unknown `tail_mode` values fail at configure time (`default` and `stat` only).
- `stat_poll_interval` applies only when `tail_mode: stat`.
- Removing `Tailer` compliance is required so acquisition dispatches through `runRestartableStream` instead of the legacy `Tailer` path.
