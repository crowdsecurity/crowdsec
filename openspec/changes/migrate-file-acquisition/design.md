## Context

See `proposal.md` — Why.

On master today the file module implements `types.Tailer` (`StreamingAcquisition` ignores context, spawns per-file goroutines via `tomb.Tomb`, and calls `tail.TailFile` from nxadm with `Follow: true`). `pkg/acquisition/acquisition.go` prefers `Tailer` over `RestartableStreamer`, so the file module never uses the context-aware restart path that `journalctl` and `syslog` already follow.

PR crowdsecurity/crowdsec#4280 is design evidence only; paths and upstream master were re-grounded in the worktree (single nxadm callsite in `run.go`, no `tail_mode` fields yet, no `openspec/specs/` catalog).

## Goals / Non-Goals

**Goals:**

- Optional `tail_mode` + `stat_poll_interval` on file `Configuration` with configure-time validation.
- In-house `tailwrapper` with context cancellation and two handle strategies: open (`KeepFileOpen: true`) and stat poll (`KeepFileOpen: false`).
- File module implements `RestartableStreamer.Stream(ctx, out)` only; drop `Tailer` compliance so acquisition uses `runRestartableStream`.
- Default path (empty or `tail_mode: default`) matches master behaviour for discovery, metrics, rotation, and line emission.
- Remove nxadm from `go.mod` once tailwrapper covers the default path.

**Non-Goals:**

- Context support in nxadm upstream.
- Changes to non-file acquisition modules.
- New OpenSpec catalog entries (no live contract).
- DSN `file://` query parameters for `tail_mode` (YAML file sources only unless tests need inline config).

## Decisions

### 1. Tail seam — `tailwrapper` package

**Choice:** New `pkg/acquisition/modules/file/tailwrapper` with `TailFile(ctx, path, Config) (Tailer, error)` and a small `Tailer` interface (`Lines() <-chan *Line`, `Stop()`, `Filename()`, `Dying() <-chan struct{}`, `Err() error`) so `run.go` can detect tailer death and surface errors.

**Rationale:** nxadm lacks context and cannot close handles between reads for stat mode. One package owns both strategies via `KeepFileOpen`.

**Alternatives rejected:** nxadm context adapter (POC dropped); upstream nxadm PR (out of scope).

### 2. Handle strategies

| `tail_mode` | `KeepFileOpen` | Behaviour |
|-------------|----------------|-----------|
| empty / `default` | `true` | Long-lived handle; reuse existing poll/inotify selection (`poll_without_inotify`, network-FS auto-detect). Equivalent to today's nxadm `Follow: true`. |
| `stat` | `false` | Stat-size poll loop; open → read new bytes → close between iterations. Interval from `stat_poll_interval`. |

Unknown `tail_mode` values fail at configure time.

### 3. `stat_poll_interval` semantics

- Only applied when `tail_mode: stat`; ignored otherwise.
- Default: `1s` when unset or `0`.
- `-1`: manual mode — no automatic ticker (tests drive reads explicitly).
- Positive durations used as-is.

### 4. Streaming API — `RestartableStreamer`

**Choice:** Implement `Stream(ctx context.Context, out chan pipeline.Event) error` using `errgroup` for monitor + per-file tail goroutines; honour `ctx.Done()` for shutdown.

**Rationale:** Matches `journalctl`/`syslog`; `acquisition.go` already wraps `Stream` with tomb-to-context bridging and restart backoff.

**Migration:** Remove `_ types.Tailer` from `init.go`; add `_ types.RestartableStreamer`. Refactor `monitorNewFiles` and `setupTailForFile` to accept `context.Context` instead of `*tomb.Tomb`. Update tests to call `Stream` (existing live-acquisition tests may still use tomb at the harness level via acquisition layer).

### 5. Default-path parity

Preserve existing knobs: `poll_without_inotify`, network-FS detection, fsnotify discovery, `discovery_poll_*`, exclude regexps, metrics labels, seek-to-end on startup. Default mode must pass current `TestLiveAcquisition/*` without behaviour regression.

### 6. Dependency removal

Drop `github.com/nxadm/tail` from `go.mod` after default-mode tailwrapper covers rotation/reopen. Recorded deviation: `[x] taken`.

## Risks / Trade-offs

- **[Stat mode latency]** → Poll interval trades handle lifetime vs line delay; document for operators on network shares.
- **[Rotation edge cases]** → Default mode must match nxadm rotation semantics; stat mode re-stat each tick — cover truncate/rename in tailwrapper tests.
- **[Acquisition dispatch order]** → Removing `Tailer` is required; if both interfaces remain, `Tailer` wins and context path is never used.
- **[Test churn]** → Live tests currently use `StreamingAcquisition`; migrate to `Stream` with context cancel.

## Migration Plan

- **Deploy:** Purely additive YAML; no migration script. Existing configs unchanged.
- **Opt-in:** Operators on network shares set `tail_mode: stat` and optionally tune `stat_poll_interval`.
- **Rollback:** Remove new YAML keys or revert branch; default path is behaviour-compatible.

## Open Questions

_(none — explore decisions ratified in propose; see `devstate/explore.md`.)_
