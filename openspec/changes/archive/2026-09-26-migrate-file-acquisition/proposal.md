## Why

File acquisition in tail mode keeps one long-lived file handle per watched log via `github.com/nxadm/tail`. That is problematic on network shares (e.g. Azure SMB) where open handles are costly or unstable. A prior POC tried to add context cancellation through nxadm directly, but the library has no context API and cannot support close-after-read stat polling cleanly.

## What Changes

- Add optional `tail_mode` (`default` | `stat`) and `stat_poll_interval` to file datasource YAML.
- Introduce `pkg/acquisition/modules/file/tailwrapper` — an in-house, context-aware tail implementation with a unified `Tailer` interface and `KeepFileOpen` flag.
- Migrate the file module from legacy `Tailer.StreamingAcquisition` + `tomb.Tomb` to `RestartableStreamer.Stream(ctx, out)` (same pattern as `journalctl` and `syslog`).
- **`tail_mode: default`** (or omitted): preserve today's open-handle behaviour — fsnotify/poll discovery unchanged, handle stays open between reads.
- **`tail_mode: stat`**: stat-poll loop that closes the file handle between reads; interval from `stat_poll_interval` (default 1s).
- Remove the `github.com/nxadm/tail` module dependency from `go.mod`.
- Extend file module tests for both tail modes and stat poll semantics.

## Capabilities

### New Capabilities

_(none — no live OpenSpec catalog in this repo; behaviour is bounded in this change folder.)_

### Modified Capabilities

_(none — `skip_specs: true`; journal in `devstate/specs.md`.)_

## Impact

- **Code:** `pkg/acquisition/modules/file/config.go`, `run.go`, `init.go`, `source.go`; new `pkg/acquisition/modules/file/tailwrapper/`; tests under `pkg/acquisition/modules/file/`.
- **Config:** optional `tail_mode` and `stat_poll_interval` on file datasources; existing YAML unchanged and behaviour-preserving when omitted.
- **Dependencies:** drop `github.com/nxadm/tail`; no new external tail library.
- **Out of scope:** other acquisition modules (`docker`, `loki`, …), upstream nxadm changes, replaying PR #4280 diff verbatim.
