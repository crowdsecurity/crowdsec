# Delivery

## Motivation

CrowdSec file acquisition in live tail mode (`mode: tail`, the default when empty) watches log files and forwards each new line into the parser pipeline. On master, each watched file gets a long-lived `github.com/nxadm/tail` tailer started from `setupTailForFile` in the file module: `tail.TailFile` with `Follow: true` keeps the file handle open for the life of the tailer, and one goroutine per file reads from that handle until shutdown.

That open-handle model works on local disks but becomes painful on network-mounted log paths. Operators tailing logs over Azure SMB (and similar network shares) see handle pressure and locking friction when CrowdSec holds a descriptor open indefinitely. The existing `poll_without_inotify` knob only switches change detection between inotify and poll inside nxadm; it does not close the handle between reads, so it does not address the underlying constraint.

A prior POC tried to wrap nxadm with context-aware cancellation, but the library has no context API and cannot implement a close-after-read stat loop cleanly. Without a replacement tail path, file acquisition cannot offer handle-light tailing for network-share deployments, and shutdown still routes through `tomb.Tomb` with a context parameter that `StreamingAcquisition` ignores.

Priority: P2 — real operator pain on network-share log paths, with limited blast radius and an unchanged default for existing configs.

## Implementation

The file module drops `github.com/nxadm/tail` and implements tailing through a new in-house `tailwrapper` package. A unified `tailer` supports two handle strategies controlled by configuration: `KeepFileOpen: true` keeps a descriptor open and uses fsnotify or poll for change detection (matching today's default behaviour), while `KeepFileOpen: false` opens, reads new bytes, and closes on each poll cycle for stat-based tailing.

Configuration adds `tail_mode` (`default` or `stat`; empty normalises to `default`) and `stat_poll_interval` (meaningful only when `tail_mode: stat`, defaulting to one second when zero). `setupTailForFile` maps `tail_mode: stat` to close-after-read mode and passes the poll interval into `tailwrapper.TailFile`.

The acquisition seam moves from `Tailer.StreamingAcquisition` with `tomb.Tomb` to `RestartableStreamer.Stream(ctx, out)` with `errgroup`: context cancellation stops the monitor loop and each per-file tail goroutine, and `Stream` blocks until all goroutines finish. Tests cover both tail modes plus the tailwrapper behaviour matrix (including truncation, rotation, and manual poll via interval `-1`).

## What this changes
**Operators.** Existing file datasource YAML needs no change; default tailing behaviour is preserved. For network-share or handle-pressure scenarios, optional `tail_mode: stat` and `stat_poll_interval` in `acquis.yaml` switch to close-after-read stat polling instead of a permanently open handle.
**Admin users.** None.
**Developers.** The file acquisition source now satisfies `RestartableStreamer` (`Stream(ctx, out)`) instead of `Tailer`; callers must use context cancellation rather than `tomb.Tomb`. New optional YAML fields are `tail_mode` and `stat_poll_interval`. The `github.com/nxadm/tail` dependency is removed from the module graph.
**End users.** None.
