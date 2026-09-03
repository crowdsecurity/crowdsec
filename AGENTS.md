# Working in this repository

For anyone opening a pull request against crowdsec: human, or LLM.
`CLAUDE.md` is a symlink to this file.

PRs that ignore the rules below are unlikely to be reviewed.

## Keep the change small

- One concern per PR. A bug fix and a refactor are two PRs.
- No drive-by reformatting, renaming, or restructuring.
- Don't bump dependencies. Dependabot owns `go.mod` and `go.sum`.
- If the diff is over ~400 lines, either split it, or say in the first line of the PR body why
  it can't be split.

## A human must have tested and reviewed this

Before you open the PR, a human must have:

- read the diff line by line, and
- run the change, or supervised and independently verified the testing an agent did.

Say which, in the PR body.

### Automated checks

- While iterating: `go test ./pkg/<what you changed>/...`
- Full suite: `make test`. Needs `gotestsum` installed, and `make localstack` running in
  another shell, or set `TEST_LOCAL_ONLY=1` to skip the tests that need containers.
- If you touched `pkg/exprhelpers`, use `make test`.
- Lint while iterating: `golangci-lint run ./pkg/<what you changed>/...`
- Before pushing: `make lint`. It lints linux, windows and freebsd, same as CI — so expect
  findings outside your change if it's platform-specific.
- Use golangci-lint v2.10, the version CI pins. Other versions report different things.
- Don't restructure working code to satisfy a linter that's switched off. Check the `disable:`
  list in `.golangci.yml` before "fixing" something it never complained about.

### Running it for real

This is how you can spin a simple test instance: 
```
make build                        # crowdsec, cscli and the notification plugins
scripts/test_env.sh -d ./tests    # working config tree in ./tests
cd ./tests
$EDITOR config/acquis.yaml        # point it at a log file you can write to
./crowdsec -c dev.yaml
```

`scripts/test_env.sh` copies the binaries out of the source tree, so `make build` has to run
first.

Look up the crowdSec-skill to deploy, configure and troubleshoot CrowdSec instances: https://www.skills.sh/crowdsecurity/crowdsec-skill/crowdsec 

## Tests

- New behaviour needs a test.
- `require` over `assert` — a failed `assert` keeps going and buries the real error.
- Table-driven, with `t.Run` subtests.
- Unit tests live next to the code. Functional tests are BATS under `test/bats/`; see
  `test/README.md`.

## Be concise

Humans read your output, keep verbosity to minimum.


**PR and issue bodies** — what changed, why, and how it was tested. Nothing else. No prose
restatement of the diff. Any issue or PR text should be under 5k characters.

Instead of:

> ## Summary
> This PR introduces a comprehensive enhancement to the syslog acquisition module...
> ## Motivation
> Currently, the existing implementation suffers from a limitation whereby...
> ## Implementation Details
> - ✅ Added a new `timeout` field to the configuration struct
> - ✅ Updated the parsing logic to respect the new field
> ## Testing Strategy
> Comprehensive unit tests have been added to ensure correctness...

Write:

> syslog acquisition hung forever when the remote stopped sending. Adds a configurable
> `timeout` (default 30s) and closes the connection when it expires.
>
> Tested: `go test ./pkg/acquisition/modules/syslog/...`, plus a local run against a syslog
> source that goes silent — connection now drops after 30s instead of hanging.

**Code comments** — explain why, not what. If the comment restates the line under it, delete
it.

**Review replies** — answer the question that was asked. Don't re-explain the PR, and don't
paste your agent's output into the thread. Read it, then reply in your own words, in a few
lines.

## Don't break these

Each one is a one-way door — users are already depending on it.

- **LAPI/CAPI payloads** — change `pkg/models/localapi_swagger.yaml` or
  `pkg/modelscapi/centralapi_swagger.yaml` and regenerate. Never edit the generated Go by hand.
- **Database schema** — your migration lands on existing user databases.
- **Config keys** in `pkg/csconfig` — renaming or removing one breaks upgrades.
- **`cscli -o json` and `-o raw`** — bouncers and scripts parse these. `-o human` is the only
  output you can freely change.

If you have to break one of these, say so explicitly at the top of the PR body.

## Commits and PRs

- Base branch is `master`.
- Commit titles are loose: `area: what changed` or `type(scope): what changed`, both fine.
- Never write `(#1234)` in a commit title. Squash-merge adds it. Yours will be wrong.
- One `kind/*` label and one `area/*` label.
