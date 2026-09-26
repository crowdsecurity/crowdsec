# Requirement
IssueKey: 2026-09-26-migrate-file-acquisition

## Problem
File acquisition keeps file handles open permanently while tailing. The ask is to migrate file acquisition tail handling and add `tail_mode` plus `stat_poll_interval` so handles do not need to stay open. A prior POC tried to migrate tail to use context, but the underlying tail library does not support context, so that approach was dropped.

## Current (code)
- `pkg/acquisition/modules/file/config.go` — `Configuration` has no `tail_mode` or `stat_poll_interval` fields; empty `mode` defaults to `configuration.TAIL_MODE`.
- `pkg/acquisition/modules/file/run.go` — `StreamingAcquisition` accepts `context.Context` but ignores it (`_ context.Context`).
- `pkg/acquisition/modules/file/run.go` — live tailing uses `github.com/nxadm/tail` via `tail.TailFile` with `Follow: true`, keeping a tailer (and file handle) open for each watched file.
- `pkg/acquisition/modules/file/run.go` — `setupTailForFile` validates the file, then starts a long-lived `tail.Tail` goroutine per file; `tails` map tracks active tailers.
- `pkg/acquisition/modules/file/run.go` — `poll_without_inotify` and network-FS detection choose inotify vs poll for the nxadm tailer; no stat-based reopen interval exists.
- `pkg/acquisition/modules/file/source.go` — `Source` holds `tails map[string]bool` and `tailMapMutex`; no tail-mode abstraction layer on master.
- `go.mod` — depends on `github.com/nxadm/tail v1.4.11`.

## Desired
- Migrate file acquisition tail handling (POC explored context-aware tail; context was removed because the library lacks support).
- Add `tail_mode` configuration to select how tailing keeps (or does not keep) file handles open.
- Add `stat_poll_interval` configuration for stat-based polling when `tail_mode` requires it.
- Preserve existing file acquisition behavior as the default path unless the new settings opt into alternate handle management.

## Affected
- `pkg/acquisition/modules/file/config.go` — new YAML fields and validation.
- `pkg/acquisition/modules/file/run.go` — tail setup, streaming acquisition loop, shutdown.
- `pkg/acquisition/modules/file/source.go` — tailer tracking if the implementation changes.
- File acquisition tests under `pkg/acquisition/modules/file/` and related acquisition config tests.

## Out of scope
- Replaying or re-specifying the full diff from stale PR #4280 (source dump only).
- Adding context support to `github.com/nxadm/tail` upstream.
- Changing non-file acquisition modules (`docker`, `loki`, etc.) that also use `TAIL_MODE`.

## Unknowns
- Exact allowed `tail_mode` values and which one is default on master today.
- Concrete tail implementation after the POC dropped context migration (replacement wrapper vs nxadm changes).
- Default and bounds for `stat_poll_interval` (including manual/disabled polling semantics).
- Backward compatibility and migration notes for existing file datasource YAML.

## Tensions
- Title and body ask for context migration, but the POC note says context was removed because the library does not support it — implementation path must reconcile that without re-adding unsupported context wiring.
