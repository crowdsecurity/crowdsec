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

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain on network-share log paths, with limited blast radius and an unchanged default for existing configs.
Reviewed head: 6ea42886
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-26-migrate-file-acquisition pushed | `git` |
| OpenSpec | migrate-file-acquisition | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec/pull/1 | pr-host |
| CI | not seen | ci-host |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: migrate file tail handling and add tail_mode / stat_poll_interval (requirement.md Desired). Out of scope: upstream nxadm context support only. → in-house pkg/acquisition/modules/file/tailwrapper and drop go.mod require on nxadm/tail. — `pkg/acquisition/modules/file/` — nxadm lacks context cancellation; stat close-after-read needs a KeepFileOpen loop PR #4280 already prototyped.. Requester: confirmed.


## Follow-up issues
None.

## How this fits together
Ticket 4280 on branch 2026-09-26-migrate-file-acquisition targeting master; PR https://github.com/david-garcia-garcia/crowdsec/pull/1; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| What are the allowed `tail_mode` values and which is the default on master today? | additive asked — new YAML field named in Desired ("Add tail_mode configuration"); empty/absent maps to current behaviour | assumed — allow `default` and `stat` only; empty or `default` is default (matches master open-handle nxadm behaviour). Reject unknown values at configure time in propose/implement. | propose |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_standards.md) — 3 total, 0 pending, 3 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_nitpicks.md) — 3 total, 0 pending, 3 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_performance.md) — 1 total, 0 pending, 1 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_dead.md) — 1 total, 0 pending, 1 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec/blob/2026-09-26-migrate-file-acquisition/devstate/2026/09/2026-09-26-migrate-file-acquisition/codereview_coverage.md) — 4 total, 0 pending, 4 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6ea42886d7f684936dde4d2cdbdde634774c375c | Card must match the branch you measured |

### Stored data model
None.
