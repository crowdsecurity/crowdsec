# Explore

## Concepts

File acquisition live mode (`mode: tail`, default when empty) tails log files and emits `pipeline.Event` lines. Master keeps one long-lived `github.com/nxadm/tail` tailer per watched file.

```
  acquis.yaml (file source)
        │
        ▼
  pkg/acquisition/acquisition.go  StartAcquisition / runTailMode
        │  Tailer.StreamingAcquisition (file module today)
        ▼
  pkg/acquisition/modules/file/run.go
        │  setupTailForFile → tail.TailFile(Follow:true)  [1 callsite]
        │  monitorNewFiles (fsnotify + optional discovery poll)
        ▼
  nxadm/tail.Tail  (goroutine per file, handle stays open)
```

**Units**

| Path | Job |
|------|-----|
| `pkg/acquisition/modules/file/config.go` | YAML for filenames, `mode`, inotify/poll knobs; no `tail_mode` yet on master |
| `pkg/acquisition/modules/file/run.go` | `StreamingAcquisition`, `setupTailForFile`, `tailFile`, `monitorNewFiles` |
| `pkg/acquisition/modules/file/source.go` | `tails map[string]bool` + mutex |
| `pkg/acquisition/types/types.go` | `Tailer` vs `RestartableStreamer` (`Stream(ctx, out)`) |
| `pkg/acquisition/acquisition.go` | Dispatches tail mode to `Tailer` first, else `RestartableStreamer` |

**Call sites (master, nxadm tail):** 1 production callsite — `setupTailForFile` in `run.go` (`tail.TailFile`). Searched worktree for `github.com/nxadm/tail` and `TailFile`: only `run.go` + `go.mod`. Tests in `pkg/acquisition/modules/file/file_test.go`.

**Reproduce:** `go test -count=1 -run "TestLiveAcquisition/(basicGlob|GlobInotify|GlobInotifyChmod)" ./pkg/acquisition/modules/file/` — PASS; nxadm logs `Re-opening moved/deleted file …` while tail active (long-lived tailer). Standalone `go run` repro against nxadm alone was inconclusive on line timing on Windows; module tests confirm live tailing.

**Outside facts:** PR crowdsecurity/crowdsec#4280 diff (design evidence for `tail_mode`, `stat_poll_interval`, tailwrapper). In-tree: `github.com/nxadm/tail` has no context API (requirement Tensions / POC note).

## Decisions

- **Seam:** add optional `tail_mode` + `stat_poll_interval` on file `Configuration`; implement tailing via new `pkg/acquisition/modules/file/tailwrapper` with context cancellation; wire `tail_mode: stat` to `KeepFileOpen: false` (stat poll loop closes handle between reads).
- **Context:** use `RestartableStreamer.Stream(ctx, out)` + `errgroup` instead of `Tailer.StreamingAcquisition` + `tomb.Tomb` — PR #4280 pattern; `acquisition.go` already supports `RestartableStreamer`.
- **Default path:** omit or `tail_mode: default` → keep current open-handle behaviour (`KeepFileOpen: true`, fsnotify/poll as today via existing `poll_without_inotify` / network-FS logic).
- **Rejected:** wrap nxadm with context adapter only — POC dropped; library lacks cancellation and cannot do close-after-read stat mode cleanly.
- **Rejected:** add context support upstream in nxadm — Out of scope on requirement.
- **Live contract:** no live contract (`openspec/specs/` absent in worktree).

## Open questions

- Q: What are the allowed `tail_mode` values and which is the default on master today?
  Rank: additive asked — new YAML field named in Desired ("Add tail_mode configuration"); empty/absent maps to current behaviour
  Decision: assumed — allow `default` and `stat` only; empty or `default` is default (matches master open-handle nxadm behaviour). Reject unknown values at configure time in propose/implement.
  By: propose

- Q: What is the concrete tail implementation after the POC dropped nxadm context migration?
  Rank: bounded asked — "Migrate file acquisition tail handling" (Desired); 1 nxadm callsite in `run.go`; PR #4280 enumerates tailwrapper package
  Decision: assumed — in-house `tailwrapper.TailFile(ctx, …)` with unified tailer (`KeepFileOpen` bool), not nxadm adapter; migrate file module to `RestartableStreamer.Stream`.
  By: propose

- Q: What are the default and bounds for `stat_poll_interval` (including manual/disabled polling)?
  Rank: additive asked — "Add stat_poll_interval configuration" (Desired)
  Decision: assumed — when `tail_mode: stat`: default 1s; `0` treated as 1s; `-1` manual/test (no automatic ticker, tests use explicit reads); only meaningful in stat mode; ignore when `tail_mode` is default.
  By: propose

- Q: What backward compatibility and migration notes apply to existing file datasource YAML?
  Rank: additive asked — "Preserve existing file acquisition behaviour as the default path unless the new settings opt into alternate handle management" (Desired)
  Decision: assumed — no YAML change required; existing configs behave as today; document optional `tail_mode: stat` + `stat_poll_interval` for network-share / handle-pressure scenarios (PR #4280 motivation: Azure SMB).
  By: propose

- Q: Should this run remove the `github.com/nxadm/tail` module dependency entirely?
  Rank: bounded incidental — no In-scope line names removal; Out of scope only forbids upstream context PR; 1 import in `run.go` (+ go.mod)
  Decision: assumed — remove nxadm from go.mod when tailwrapper lands; deviation recorded.
  By: propose
