## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 81c6f1e8
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
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec/pull/1 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- proposed: migrate file tail handling and add tail_mode / stat_poll_interval (requirement.md Desired). Out of scope: upstream nxadm context support only. → in-house pkg/acquisition/modules/file/tailwrapper and drop go.mod require on nxadm/tail. — `pkg/acquisition/modules/file/` — nxadm lacks context cancellation; stat close-after-read needs a KeepFileOpen loop PR #4280 already prototyped.. Awaiting the requester.


## Follow-up issues
None.

## How this fits together
Ticket 4280 on branch 2026-09-26-migrate-file-acquisition targeting master; PR https://github.com/david-garcia-garcia/crowdsec/pull/1; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| What are the allowed `tail_mode` values and which is the default on master today? | additive asked — new YAML field named in Desired ("Add tail_mode configuration"); empty/absent maps to current behaviour | assumed — allow `default` and `stat` only; empty or `default` is default (matches master open-handle nxadm behaviour). Reject unknown values at configure time in propose/implement. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 81c6f1e8be0f88db6261e7f6b1d0ed6cfeb5ead1 | Card must match the branch you measured |

### Stored data model
None.
