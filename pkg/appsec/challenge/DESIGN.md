# WAF Bot Detection / Challenge — Design, Review, Usage

This document covers the CrowdSec WAF challenge subsystem: how it is built, what
reviewers should look for when touching it, and how operators / collection
authors are expected to use it.

The implementation lives under [pkg/appsec/challenge](.) and is wired into the
acquisition pipeline by [pkg/acquisition/modules/appsec](../../acquisition/modules/appsec).

---

## 1. Design

### 1.1 What the feature does

The challenge subsystem lets the WAF interpose a browser-side proof-of-work +
device-fingerprint check between a visitor and the protected origin. A visitor
who solves the challenge receives a sealed cookie carrying their measured
fingerprint; subsequent requests from the same browser can be evaluated by
operator-defined hooks (`on_challenge`, `on_challenge_submit`) without
re-challenging.

The challenge runtime is built **lazily**: it only spins up if at least one
loaded hook calls `SendChallenge()`, `GrantChallengeCookie()`, or
`RejectSubmission()`. This is detected by [`appsecExprPatcher`](../patcher.go)
walking the compiled expression AST and setting
`AppsecRuntimeConfig.NeedWASMVM`.

### 1.2 Component map

```
┌──────────────────────────────────────────────────────────────────────┐
│ Acquisition module (pkg/acquisition/modules/appsec/config.go)        │
│   - HTTP listener, ParsedRequest plumbing                            │
│   - Loads appsec-config(s), builds AppsecRuntimeConfig               │
│   - If NeedWASMVM: challenge.BuildOptions → NewChallengeRuntime      │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ pkg/appsec (AppsecConfig / AppsecRuntimeConfig)                      │
│   - YAML schema, hook compilation, request-lifecycle dispatcher      │
│   - ProcessOnChallengeRules: cookie validation, /submit handling     │
│   - SendChallenge / GrantChallengeCookie / RejectSubmission helpers  │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ pkg/appsec/challenge (ChallengeRuntime)                              │
│   - KeyRing: HKDF-derived per-epoch keys + long-lived cookie key     │
│   - Crypto: AES-GCM cookie seal/open, ticket + PoW MAC HMACs         │
│   - Obfuscator: wazero-hosted WASM running javascript-obfuscator     │
│   - Static bundle pool: baked-in + optional runtime variants         │
│   - Dynamic module pool: per-epoch key script, obfuscated variants   │
│   - Fingerprint mismatch report aggregator                           │
└──────────────────────────────────────────────────────────────────────┘
```

### 1.3 Configuration model

Challenge tuning lives **inside the appsec-config**, not the acquisition
config. The relevant fields are on [`challenge.Config`](config.go), referenced
from `AppsecConfig.Challenge`:

```go
type Config struct {
    MasterSecret                      *string
    KeyRotationInterval               *time.Duration
    MaxLiveEpochs                     *int
    CookieTTL                         *time.Duration
    CryptoObfuscationPoolSize         *int
    LibraryRuntimeObfuscationEnabled  *bool
    LibraryObfuscationPoolSize        *int
    LibraryObfuscationRefreshInterval *time.Duration
}
```

All fields are pointer-typed so the YAML loader can distinguish *unset* from
*zero* — necessary because multiple appsec-configs can each contribute a
disjoint subset of fields. `LoadByPath` merges per field (last non-nil wins),
matching the existing "append rules, override scalars" pattern used elsewhere
in the appsec-config loader.

`challenge.BuildOptions(c *Config) ([]Option, error)` translates the merged
config into the option list consumed by `NewChallengeRuntime`. Unset fields
produce no option and the runtime falls back to its built-in default. An
invalid `master_secret` surfaces as a configuration error rather than silently
falling back to a random secret (which would be a footgun in distributed
deployments).

### 1.4 Cryptographic core

#### Master secret

- Configured as hex (preferred — even-length, hex digits only) or as a
  passphrase. Both forms must be at least **32 bytes** decoded — the natural
  minimum for HMAC-SHA256 with full security margin.
- If unconfigured, [`generateRandomSecret`](secret.go) produces a fresh 32-byte
  secret and the runtime logs a warning. Suitable only for single-instance
  deployments: a restart invalidates outstanding cookies, and distributed
  WAFs can't agree on the same value.

#### KeyRing — per-epoch derivation

[`pkg/appsec/challenge/keyring.go`](keyring.go) derives two independent key
families from the master secret via HKDF-SHA256 (salt
`"crowdsec-challenge-keyring-v1"`):

| Family | HKDF info | Lifetime | Use |
|---|---|---|---|
| Per-epoch sign key | `"epoch-sign"` | One rotation interval | Ticket HMAC, PoW MAC |
| Master cookie key | `"cookie-master"` | Lifetime of master secret | AES-GCM seal/open of challenge cookies |

An **epoch** is a time bucket of `rotationInterval` seconds, computed as
`now.Unix() / rotation_interval_seconds`. All instances sharing the same
master secret + rotation interval derive bit-identical epoch keys with no
coordination — the basis for stateless distributed verification.

The keyring keeps a sliding window of `MaxLiveEpochs` past epochs plus the
current epoch plus a one-step clock-skew slack. Submissions signed by any key
inside the live window verify; older ones are rejected. Cached entries
outside the window are evicted whenever a new epoch is derived.

Defaults: `keyringDefaultRotation = 5 minutes`, `keyringDefaultMaxLive = 3`,
`keyringMinRotation = 30 seconds`.

#### Cookie envelope (v0)

[`pkg/appsec/challenge/crypto.go`](crypto.go) seals cookies under the
long-lived master cookie key with AES-256-GCM:

```
wire format: version_byte(1) || nonce(12) || ciphertext
plaintext  : not_after_be8(8) || flags(1) || reason_len_be(2)
                              || reason_bytes(0..256)
                              || protobuf_envelope
AAD        : user-agent bytes
```

Three things to note:

1. **Cookie expiry is enforced by the embedded `not_after` timestamp**, not
   by keyring eviction. This intentional decouples cookie TTL (operator
   policy, e.g. 12h–24h) from the keyring live window (forgery exposure, e.g.
   15m). Long-lived cookies don't widen the ticket-signing forgery window.
2. **User-Agent is the GCM authentication tag.** A cookie cannot be replayed
   across UAs — `openCookie` fails authentication on mismatch.
3. **Allowlist cookies** set `cookieFlagAllowlisted = 0x01` and carry an
   operator reason (`MaxAllowlistReasonLen = 256` bytes — bounded to keep the
   final cookie comfortably under the browser 4 KB limit). Real-submission
   cookies leave the flag clear and the reason empty.

#### Ticket and PoW MAC

[`pkg/appsec/challenge/ticket.go`](ticket.go) signs each challenge render
with two HMAC-SHA256 tags computed from the per-epoch key:

- `ticket = HMAC(K_epoch, ts_nanos_string)`
- `powMAC = HMAC(K_epoch, salt || ticket || ts)`

`ts` is just `time.Now().UnixNano()` formatted as a string; the verifier
derives the epoch from `ts` itself and looks up the same key. There is no
server-side state — any instance with the same master secret + rotation
interval can validate any other's tickets.

Freshness is doubly gated: keyring liveness (epoch in live window) and a
loose backstop of `ticketAgeBackstop = 20 minutes`.

PoW levels (in leading SHA-256 zero bits) live as constants in
[`ticket.go`](ticket.go):

| Level | Bits | Approx work |
|---|---|---|
| `Disabled` | 0 | nonce `"0"` always valid |
| `Low` | 10 | ~1k hashes, 0.2–2 s |
| `Medium` (default) | 12 | ~4k hashes, 1–8 s |
| `High` | 15 | ~32k hashes, 7–60 s |
| `Impossible` | 256 | unsolvable — hard block |

### 1.5 JS obfuscation pipeline

The browser receives three logical pieces of JS at every challenge:

1. **Static library bundle** — fpscanner + PoW worker glue + IndexedDB
   persistence. Public, non-sensitive code.
2. **Dynamic key module** — a ~30-line script embedding the current epoch's
   HMAC signing key as a hex literal, so the client can compute a ticket for
   the submission.
3. **PoW worker** — separate JS served at `/crowdsec-internal/challenge/pow-worker.js`.

#### The obfuscator itself

A pre-built `javascript-obfuscator` distribution compiled to WASM lives at
[`js/obfuscate/index.wasm.gz`](js/obfuscate) (regeneration is wired through
`go:generate` in [`js/generate.go`](js/generate.go)). At runtime
[`obfuscator.go`](obfuscator.go) hosts it under [wazero](https://wazero.io):

- The WASM module is **decompressed and compiled once** at startup
  (`CompileModule` ~4–5 s); per-call cost is just `InstantiateModule`.
- Each obfuscation pass produces byte-distinct output even for the same input
  (mangled identifier names, random transforms).
- A pass on the **static library bundle** takes ~1 min of CPU; a pass on the
  **dynamic module** takes ~5 s.

#### Static bundle pool

The library bundle is **always** obfuscated — `initial_bundle.js.gz` is
generated at build time by [`js/cmd/initialbundle`](js/cmd/initialbundle)
(run via `go generate`) and embedded into the binary.
[`static_bundle.go`](static_bundle.go) seeds the pool with that variant on
startup. By default the pool stays at size 1 and no further runtime
obfuscation happens — the baked-in variant is what every visitor receives.

With `library_runtime_obfuscation_enabled: true`, a background goroutine
adds one new runtime-obfuscated variant per
`library_obfuscation_refresh_interval` (default 1 h), capped at
`library_obfuscation_pool_size` (default 1, raise it together with the
flag to grow the pool). Each challenge render picks a variant at random.

The name `library_runtime_obfuscation_enabled` is precise on purpose: the
library is obfuscated regardless of the flag — the flag only adds runtime
*variants*. If runtime obfuscation is off and `library_obfuscation_pool_size`
is > 1, the runtime warns at startup and clamps the pool to 1 (the extra
slots would never be filled since only the initial bundle seeds the
pool).

#### Dynamic module pool

[`dynamic_module.go`](dynamic_module.go) renders a small template
([`dynamic_module.js.tmpl`](dynamic_module.js.tmpl)) with the current epoch's
key + epoch number, obfuscates it, and caches `crypto_obfuscation_pool_size`
variants per live epoch.

Two non-obvious mechanisms keep this fast:

- **`singleflight` deduplication**: if N concurrent requests arrive right
  after a rotation, only one runs the obfuscator per variant slot; the others
  block on its result. Worst-case latency at the rotation boundary is one
  obfuscation pass, not N serialized passes.
- **Pre-warming**: a goroutine fires `1/4 × rotation_interval` before each
  boundary (capped 1–30 s) and obfuscates the full pool for the upcoming
  epoch. The first request after rotation finds the cache populated.

The obfuscator config (in [`js/obfuscate/obfuscate.js`](js/obfuscate))
reserves the hook symbol `__CSEC_CHALLENGE_HOOK_v1__` so the static and
dynamic modules can find each other by name across independent obfuscation
passes. The key material itself is **not** reserved — it's deliberately
encoded by the obfuscator's string-array transforms.

### 1.6 Request lifecycle

The acquisition module's `appsecHandler` parses every incoming HTTP request
into a `ParsedRequest` and pushes it into the runner pool. Each runner calls
`AppsecRunner.ProcessInBandRules`, which **first** invokes
`AppsecRuntimeConfig.ProcessOnChallengeRules` and only proceeds to WAF
evaluation if no challenge response was assembled.

`ProcessOnChallengeRules` dispatches three cases:

| Path | Method | Handling |
|---|---|---|
| `/crowdsec-internal/challenge/pow-worker.js` | GET | Static `PowWorkerJS` body served |
| `/crowdsec-internal/challenge/submit` | POST | `ValidateChallengeResponse` → fingerprint decrypt → `on_challenge_submit` hooks → `bodyChallengeOK` + Set-Cookie *or* `bodyChallengeRejected` |
| anything else | any | Existing `__crowdsec_challenge` cookie validated → `state.Fingerprint` populated → `on_challenge` hooks |

For a submission, `ValidateChallengeResponse`:

1. Parses the form (`f, t, ts, h, n, p, m` — encrypted fingerprint, client
   ticket, timestamp, HMAC, nonce, PoW salt, PoW MAC).
2. Calls `matchesChallenge` to derive the epoch from `ts`, look up the
   per-epoch key, verify `t == HMAC(K_epoch, ts)` and `m == HMAC(K_epoch,
   p || t || ts)`.
3. Rejects outright if difficulty is `Impossible`.
4. Verifies the PoW: `hasLeadingZeroBits(SHA-256(p || n), powDifficulty)`.
5. Derives the session key as `SHA-256(t || n)`, verifies the HMAC over the
   encrypted fingerprint, decrypts it (XOR keystream), and JSON-unmarshals
   into `FingerprintData`.
6. Seals a v0 cookie carrying that fingerprint under the long-lived master
   cookie key with a fresh `not_after`.

The challenge page itself (`GetChallengePage`) builds the response by:

1. Resolving difficulty (per-request override beats runtime default).
2. Picking a random static library bundle variant and a random dynamic
   module variant.
3. Generating `ts`, `ticket`, `powSalt`, `powMAC`.
4. Rendering [`challenge.html.tmpl`](challenge.html.tmpl) with all of the
   above.

### 1.7 Hook surface

Six hook stages, two of which are challenge-specific:

| Hook | When | Env | Notable helpers |
|---|---|---|---|
| `on_load` | Engine startup, once | runtime config | `SetChallengeDifficulty` (sets runtime default) |
| `pre_eval` | Before WAF | request + state | `SendChallenge`, `GrantChallengeCookie(reason, ttl?)`, `SetChallengeDifficulty` (per-req) |
| `post_eval` | After WAF | request + state | same as `pre_eval` |
| `on_match` | Per-rule match | event + state | `SetRemediation`, `SetReturnCode` |
| `on_challenge` | Valid cookie/submission, fingerprint available | fingerprint + state | `SendChallenge`, `SetChallengeDifficulty`, `EvaluateMismatches`, `fingerprint.*` |
| `on_challenge_submit` | POST `/submit` after crypto validation | fingerprint + state | `RejectSubmission`, `GrantChallengeCookie(reason, ttl?)` (inline), `EvaluateMismatches` |

`on_challenge` is skipped if `state.Fingerprint` is nil (no valid cookie or
submission). `on_challenge_submit` is deliberately narrow: only helpers that
preserve the challenge-submit JSON envelope shape are exposed — a 307 redirect
from this phase would break the client JS state machine.

### 1.8 Fingerprint mismatch report

[`fingerprint_mismatch.go`](fingerprint_mismatch.go) aggregates two families
of signals into a `MismatchReport`:

**Library-native** (from `fpscanner`):
CDP, WebDriver flavours, Selenium, Playwright, headless Chrome, impossible
memory, high CPU count, WebGL/GPU/platform mismatches, bot user-agent —
mostly *high* severity. UTC timezone is *medium*; swiftshader and language
mismatches are *low*.

**Custom helpers**:

- `UAMobileMismatch()` — UA claims mobile but inner viewport ≥ 1024 px
  (catches desktop UA switchers). Medium.
- `AcceptLanguageMismatch(req)` — request `Accept-Language` base differs from
  `navigator.language` base. Medium.
- `TimezoneCountryMismatch(country)` — timezone not valid for GeoIP-derived
  country. Low (travellers / VPNs legitimately trigger it).

`EvaluateMismatches()` is the hook-side entry point; it caches the result on
`state.LastMismatchReport` so chained calls like
`EvaluateMismatches().High() >= 1 && EvaluateMismatches().Has("cdp")` don't
recompute. First call also emits a debug log line and bumps per-signal
Prometheus counters.

### 1.9 Allowlist bypass

`GrantChallengeCookie(reason, ttl?)` is the operator escape hatch for trusted
clients (Googlebot, internal probes, paying partners…). It mints a sealed
cookie with the `cookieFlagAllowlisted` bit set and the operator reason
embedded, stamps a synthetic `Allowlisted` fingerprint on `state.Fingerprint`,
and flips `state.ChallengeBypassed` so any later `SendChallenge` in the same
request is a no-op.

Two variants, both exposed under the same name to the operator:

- In `pre_eval` / `post_eval`: issues HTTP 307 to the same URI with the
  cookie attached. The visitor bounces back through the WAF with the cookie
  present and the next iteration short-circuits on the allowlist branch.
  Required because plain `AllowRemediation` responses don't carry cookies
  through the bouncer protocol; only `ChallengeRemediation` does.
- In `on_challenge_submit`: appends the cookie to the existing
  `{"status":"ok"}` JSON envelope.

The optional `ttl` argument is parsed via `time.ParseDuration` and overrides
the runtime-global `cookie_ttl` for that single cookie only. Empty / missing
falls back to the runtime default; malformed / non-positive surfaces as an
expression error so authors see a precise diagnostic.

### 1.10 Decision logging

Accept / reject decisions go through `FingerprintData.LogAccepted` /
`LogRejected` in [`fingerprint_helpers.go`](fingerprint_helpers.go).
Both are nil-safe; the caller picks the log level (Debug for
per-request sites, Info for rarer / operator-authored events).

The asymmetry to remember when reading these helpers: **accept logs
always emit the baseline flags** (`is_bot`, `allowlisted`) so a clean
acceptance is explicit, while **reject logs emit only positive
information** — `"headless": false` is noise on a forensic artefact.
`signals` is enumerated by walking `libDetections`, so it cannot
drift from `MismatchReport.Reasons()`.

For submit-phase events the verbosity is operator-controlled via the
expr helpers `RejectSubmission(reason, verbosity?)` and
`LogAccepted(msg, verbosity?)` (see §3.2); both helpers log at Info,
and the verbosity argument tunes only the field-set richness, not the
level. `ValidateChallengeResponse` in `challenge.go` is deliberately
silent on the success path — the caller in `appsec.go` (and the expr
wrappers in `waf_helpers.go`) own the `*log.Entry`, so they own the
accept / reject log.

For the field reference and example output, see §3.1.

---

## 2. Review guidelines

Things to actively look for when reviewing changes that touch this subsystem.

### 2.1 Invariants that must not break

- **Stateless distributed verification.** Anything written into a ticket,
  PoW MAC, or cookie must be derivable from the master secret + epoch +
  request data. No node-local randomness, no node-specific identifiers.
  Multiple WAFs sharing a master secret must accept each other's submissions
  silently.
- **`master_secret` policy.** A misconfigured master_secret must FAIL the
  config load — it must never silently fall back to a random secret when the
  operator clearly intended to set one. The "random secret" path is reserved
  for the *no `master_secret` at all* case, and must always emit the existing
  warning. [`BuildOptions`](config.go) bubbles `ParseConfiguredSecret` errors
  for this reason.
- **Cookie / keyring decoupling.** Cookie TTL is enforced inside the sealed
  envelope (`not_after`), not by keyring eviction. Don't tie cookie validity
  to live-epoch membership — that would force cookie TTL ≤ keyring window,
  which is the opposite of what the design wants.
- **User-Agent AAD.** Removing the UA AAD from `sealCookieV0` / `openCookie`
  breaks cookie-binding-to-browser. If a change wants per-UA tolerance,
  introduce a *separate* validation path; don't loosen the GCM tag.
- **`NeedWASMVM` detection coverage.** Any new expr helper that needs the
  challenge runtime must be added to `challengeRuntimeCallees` in
  [`patcher.go`](../patcher.go). Forgetting this lets a hook reference a
  helper without spinning the runtime up at all — `nil` deref at request
  time.
- **`state.ChallengeBypassed` honor.** Helpers that produce a challenge
  response (`SendChallenge`, future variants) must early-return when
  `ChallengeBypassed` is set. Two `Set-Cookie`s and a redirect with a body
  is incoherent for the bouncer protocol.
- **`on_challenge_submit` narrowness.** The submit-phase env intentionally
  omits `SendChallenge`, `SetRemediation`, `SetReturnCode`,
  `SetChallengeDifficulty`, `DropRequest`. Adding any of these here will
  silently break the client JS state machine. If you need this behaviour,
  set state and let the *next* request's `pre_eval` act on it.

### 2.2 Concurrency hazards

- **Dynamic module pool**: writes go through `singleflight` and a mutex.
  Don't bypass either. Walking `dynamicModuleCache` without holding
  `dynamicModuleCacheMu` is a race; mutating it inside a
  `singleflight.Do` callback is fine.
- **Library bundle pool**: `libraryBundlePoolMu` is `RWMutex`. The refresher
  goroutine takes the write lock to append + trim; read paths must use the
  read lock. Pool size must always stay ≤ `libraryPoolSize` after a refresh
  pass.
- **Pre-warmer lifetime**: the pre-warmer reads from the keyring and writes
  into the dynamic module cache. It must observe context cancellation. If
  you add a new goroutine, plumb the same context.
- **Obfuscator instantiation**: `Runtime.InstantiateModule` is safe to call
  concurrently against the same `CompiledModule`; the actual JS execution
  isn't a concern because each call gets its own module instance.

### 2.3 Performance and resource shape

- **Compile-once, instantiate-per-call** is the established WASM pattern.
  If a change moves WASM compilation onto the request path, that adds ~4–5
  seconds of CPU per challenge served.
- **Pool sizes have CPU cost**, not just memory cost. Each
  `crypto_obfuscation_pool_size` increment is one extra ~5 s obfuscation
  pass per epoch rotation. Each `library_obfuscation_pool_size` increment is
  one extra ~1 min pass per `library_obfuscation_refresh_interval`.
- **Pre-warm lead time** is `1/4 × rotation_interval`, capped at 30 s and
  floored at 1 s. Shrinking the rotation interval below ~20 s makes the
  pre-warmer too tight for the obfuscation pass; the test
  `TestCryptoObfuscationPoolSize` in
  [obfuscation_pools_test.go](obfuscation_pools_test.go) is currently
  flaky around this boundary and is unrelated to most config changes.

### 2.4 Config and merge semantics

- **`challenge.Config` fields must stay pointer-typed.** Switching a field
  to a value type breaks the multi-config merge — `MergeFrom` relies on
  `nil` to mean "unset, keep dst's value". A `bool` value type would always
  look set to `false`.
- **`LoadByPath` merge order is "last wins" per field.** Tests asserting
  this live in `pkg/appsec/appsec_config_test.go::TestLoadByPathChallengeBlockMergesAcrossFiles`.
  Don't switch to first-wins or error-on-conflict without an explicit
  design decision — collection composability depends on it.
- **YAML strict parsing.** [`Source.UnmarshalConfig`](../../acquisition/modules/appsec/config.go)
  uses `yaml.Strict()`. This is the desired loud-failure surface for stale
  `challenge_*` keys in acquisition YAML left over from earlier branches.
  Don't loosen it.

### 2.5 Test hooks

Targeted tests live alongside the code:

- [`config_test.go`](config_test.go) — `MergeFrom`, `BuildOptions`,
  per-call cookie TTL override.
- [`challenge_test.go`](challenge_test.go) — leading-zero-bits PoW check,
  end-to-end render/submit.
- [`keyring_test.go`](keyring_test.go) + [`keyring_integration_test.go`](keyring_integration_test.go)
   — epoch math, key derivation determinism, liveness window.
- [`secret_test.go`](secret_test.go) — hex vs passphrase, min-size guard.
- [`initial_bundle_test.go`](initial_bundle_test.go), [`split_bundle_test.go`](split_bundle_test.go)
   — baked-in bundle integrity.
- [`obfuscation_pools_test.go`](obfuscation_pools_test.go) — library and
  dynamic pool behaviour (note: `TestCryptoObfuscationPoolSize` is flaky;
  it depends on the JS obfuscator producing byte-distinct output across
  passes).
- [`pkg/appsec/appsec_challenge_test.go`](../appsec_challenge_test.go) —
  `GrantChallengeCookie` 307 path, inline submit variant,
  `state.ChallengeBypassed` guard, allowlist flag propagation.
- [`pkg/appsec/waf_helpers_test.go`](../waf_helpers_test.go) — TTL
  argument parsing.

Run subsets when iterating:

```
go test ./pkg/appsec/challenge/ -run 'TestConfig|TestBuildOptions|TestSealAllowlistCookieTTLOverride'
go test ./pkg/appsec/ -run 'TestGrantChallengeCookie|TestProcessOnChallengeRules'
```

The combined `./pkg/appsec/... ./pkg/acquisition/modules/appsec/...` run
hits ~10 min wall clock because of the obfuscation passes; expect to time
out unless you split by package.

### 2.6 Things that look wrong but aren't

- `GrantChallengeCookie` issues a **307** even though it semantically
  *allows* the visitor. This is because the bouncer protocol only
  serialises `UserCookies` on a `ChallengeRemediation` response; a plain
  `AllowRemediation` would drop the `Set-Cookie`. The 307 is the
  minimal-friction way to deliver the cookie *and* bounce the visitor
  through the WAF a second time so the allowlist branch hits.
- `mintAllowlistCookie` deliberately **overwrites any prior `state.Fingerprint`**
  set by the cookie-valid branch. Operator-explicit allowlist beats a
  pre-existing real-submission fingerprint. Filter on `req.Headers` *before*
  the allowlist rule fires if you want the real signal preserved.
- The dynamic module template embeds the per-epoch key as a hex literal in
  plain JS source before obfuscation. That's intentional — the obfuscator's
  string-array transforms encode it, and per-epoch rotation bounds the
  exposure.

---

## 3. Intended usage

This section is for collection authors and operators shipping bot
detection.

### 3.1 Minimal collection setup

Install a collection that ships an appsec-config exercising the challenge
hooks:

```sh
cscli collections install crowdsecurity/appsec-bot-detection
```

A complete appsec-config for the feature looks like:

```yaml
name: crowdsecurity/appsec-bot-detection
default_remediation: ban

inband_rules:
  - crowdsecurity/base-config
  - crowdsecurity/vpatch-*

challenge:
  # Required for distributed (multi-WAF) deployments. Hex (preferred) or
  # passphrase; min 32 bytes / characters. If unset the runtime generates an
  # ephemeral random secret and logs a warning (single-instance only).
  master_secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

  # Optional tuning — defaults shown.
  key_rotation_interval: 5m
  max_live_epochs: 3
  cookie_ttl: 12h
  crypto_obfuscation_pool_size: 1
  # The library bundle is ALWAYS obfuscated (build-time). This flag only
  # adds further runtime-generated variants — leave off unless you want
  # per-visitor byte variance on top of the build-time obfuscation.
  library_runtime_obfuscation_enabled: false
  # library_obfuscation_pool_size: 1        # clamped to 1 when runtime obfuscation is off
  # library_obfuscation_refresh_interval: 1h # ignored when runtime obfuscation is off

# Hooks define WHEN to challenge and WHO gets allowlisted.
inband:
  pre_eval:
    # Allowlist trusted reverse-resolved Googlebot. Mint a 24h cookie
    # explicitly with the optional TTL argument.
    - filter: "req.Headers.Get('User-Agent') contains 'Googlebot'"
      apply:
        - GrantChallengeCookie("Googlebot", "24h")

    # Challenge everything else with a measurable fingerprint signal we want
    # to inspect on subsequent requests.
    - filter: "true"
      apply:
        - SendChallenge()

  on_challenge:
    # After a valid submission OR cookie present: escalate to ban if the
    # fingerprint exhibits strong bot indicators.
    - filter: "EvaluateMismatches().High() >= 1 || EvaluateMismatches().Has('cdp')"
      apply:
        - SetRemediation("ban")

    # Soft escalation: raise difficulty on weak signals.
    - filter: "EvaluateMismatches().Medium() >= 2"
      apply:
        - SetChallengeDifficulty("high")
        - SendChallenge()

  on_challenge_submit:
    # Catch automation that solves the PoW but fails atomic fingerprint
    # consistency checks. Refuse to issue a cookie for these and dump
    # the full fingerprint detail into the reject log.
    - filter: "fingerprint.UAMobileMismatch() || fingerprint.AcceptLanguageMismatch(req)"
      apply:
        - RejectSubmission("ua_or_lang_mismatch", "verbose")

    # Clean submission: log the acceptance with default-verbosity fields
    # so operators have an auditable accept event per visitor.
    - filter: "true"
      apply:
        - LogAccepted("challenge submission accepted")
```

#### What the decision logs look like

Every fingerprint accept / reject above produces a structured log
entry via `FingerprintData.LogAccepted` / `LogRejected`. Operators
correlate on `fsid` / `source` and can index these directly.

Examples at the default `"info"` verbosity (what the expr helpers
`LogAccepted` / `RejectSubmission` emit when called without a second
argument):

```
level=info msg="challenge submission accepted" source=203.0.113.7 fsid=FS1_abc ua="Mozilla/5.0…" platform=macOS is_bot=false signals="[]" allowlisted=false is_mobile=false
level=info msg="on_challenge_submit rejected" source=203.0.113.7 fsid=FS1_abc reason=ua_or_lang_mismatch ua="Mozilla/5.0…" platform=macOS signals="[cdp]" automation=true
level=info msg="granted allowlist challenge cookie via 307 redirect" source=66.249.66.1 location=/ ua="Googlebot/2.1" allowlisted=true allowlist_reason=Googlebot signals="[]"
level=debug msg="valid challenge cookie" source=203.0.113.7 fsid=FS1_abc ua="Mozilla/5.0…" platform=macOS is_bot=false signals="[]" allowlisted=false
```

The verbosity string (`"minimal"`, `"info"` default, `"verbose"`) is
passed as the optional last argument to both `LogAccepted` and
`RejectSubmission`. Bad values emit a warning and fall back to
`"info"`.

**Always present (`"minimal"` verbosity):**

| Field | Type | Notes |
|---|---|---|
| `source` | string | Client IP (`request.RemoteAddrNormalized`) — same field name as `fingerprint mismatch` logs for correlation |
| `fsid` | string | Per-fingerprint identifier; omitted when empty |
| `ua` | string | Browser-reported User-Agent; omitted when empty |
| `platform` | string | High-entropy client-hint platform, falling back to `navigator.platform`; omitted when empty |
| `is_bot` | bool (accept) / only-if-true (reject) | Library fast-bot verdict |
| `signals` | `[]string` | Names of library bot signals that fired (e.g. `["cdp", "headless_screen_resolution"]`); empty on clean fingerprints. Enumerated from `libDetections`, so always in sync with `MismatchReport.Reasons()` |
| `allowlisted` | bool (accept) / only-if-true (reject) | True for cookies minted by `GrantChallengeCookie` |
| `allowlist_reason` | string | Present only when `allowlisted == true` and the reason is non-empty |
| `reason` | string | **Reject-only**, always present. The operator-facing cause (e.g. the string passed to `RejectSubmission`) |

**`"info"` verbosity adds** `is_mobile` plus the category roll-ups
(`automation` / `headless` / `mismatch` / `impossible_device`); the
roll-ups only appear when they fired.

**`"verbose"` verbosity adds** `timezone`, `language`, `cpu_count`,
`memory`, `url`, `nonce`, `fp_time`. Zero / empty values are omitted.

Custom mismatches (`UAMobileMismatch`, `AcceptLanguageMismatch`,
`TimezoneCountryMismatch`) are **not** in `signals` — they need
request / geo context and are emitted separately on the `fingerprint
mismatch` line, with their own `reasons` field. Correlate on `fsid` /
`source`.

### 3.2 YAML field reference

#### `challenge:` block

| Key | Type | Default | Notes |
|---|---|---|---|
| `master_secret` | string | random + warning | Hex (preferred) or passphrase, ≥ 32 bytes |
| `key_rotation_interval` | duration | 5m | Min 30 s; must be the same across all instances |
| `max_live_epochs` | int | 3 | Past epochs accepted; sized to cover the freshness window |
| `cookie_ttl` | duration | 12h | Decoupled from rotation interval; can be long (24h+) |
| `crypto_obfuscation_pool_size` | int | 1 | Variants of dynamic key module per epoch; each costs ~5 s of CPU per rotation |
| `library_runtime_obfuscation_enabled` | bool | false | Enable *runtime* library re-obfuscation. The library bundle is always obfuscated at build time regardless of this flag; this only adds further variants over time |
| `library_obfuscation_pool_size` | int | 1 | Pool ceiling for library variants. Values > 1 are only meaningful when runtime obfuscation is enabled; otherwise the runtime warns and clamps to 1 |
| `library_obfuscation_refresh_interval` | duration | 1h | Cadence; ignored when runtime obfuscation is off. Full pool rotation = `pool_size × interval` |

#### Hook helpers

| Helper | Available in | Effect |
|---|---|---|
| `SendChallenge()` | `pre_eval`, `post_eval`, `on_challenge` | Serve a challenge page (no-op if visitor already passed an equal-or-harder PoW, or `ChallengeBypassed`) |
| `GrantChallengeCookie(reason, ttl?)` | `pre_eval`, `post_eval` | Mint allowlist cookie + 307 redirect |
| `GrantChallengeCookie(reason, ttl?)` | `on_challenge_submit` | Mint allowlist cookie inline on submit response |
| `RejectSubmission(reason, verbosity?)` | `on_challenge_submit` | Refuse to issue cookie for an otherwise-valid submission; emits an Info reject log immediately. `verbosity ∈ {minimal, info (default), verbose}` controls how much fingerprint detail rides on the log; bad values warn and fall back to info |
| `LogAccepted(msg, verbosity?)` | `on_challenge_submit` | Emit an Info accept log with the current fingerprint. Same `verbosity` vocabulary as `RejectSubmission`. No-op when no fingerprint is present |
| `SetChallengeDifficulty(level)` | `on_load` | Set runtime default (`"disabled"`, `"low"`, `"medium"`, `"high"`, `"impossible"`) |
| `SetChallengeDifficulty(level)` | `pre_eval`, `post_eval`, `on_challenge` | Per-request override (does NOT change runtime default) |
| `EvaluateMismatches()` | `on_challenge`, `on_challenge_submit` | Returns `MismatchReport`; cached per request |
| `fingerprint.UAMobileMismatch()` | wherever `fingerprint` is non-nil | Atomic check, no aggregation |
| `fingerprint.AcceptLanguageMismatch(req)` | same | Atomic check |
| `fingerprint.TimezoneCountryMismatch(country)` | same | Atomic check |

#### `MismatchReport` API

```
.Count()              total signals fired
.Empty()              true if none fired
.High() / .Medium() / .Low()   count by severity
.BySeverity(s)        count for "high" / "medium" / "low"
.Has(reason)          true if a specific signal fired
.Reasons()            stable-ordered list of fired reason keys
.String()             "reason1(sev),reason2(sev)" — handy for logs
```

### 3.3 Multi-config composition

Multiple appsec-configs can be merged by listing them in acquisition:

```yaml
# acquis.yaml
appsec_configs:
  - crowdsecurity/appsec-default       # base rules, no challenge block
  - crowdsecurity/appsec-bot-detection # challenge block + hooks
  - mycorp/internal-allowlist          # adds an extra pre_eval hook
```

Within the `challenge:` block, **each later config's non-nil fields override
earlier ones, field by field.** A collection that only wants to ship a
specific `cookie_ttl` can do so without redeclaring the rest:

```yaml
# mycorp/short-cookie-overlay
name: mycorp/short-cookie-overlay
challenge:
  cookie_ttl: 30m   # overrides whatever the upstream config set
```

Other top-level YAML keys follow the existing appsec-config patterns: rules
and hooks are *appended* across configs; scalars like `default_remediation`,
HTTP codes, and challenge fields are *overridden*.

### 3.4 Single-instance vs distributed deployment

| Scenario | What to do |
|---|---|
| Single WAF, dev | Skip `master_secret` entirely. Ephemeral cookies on restart, warning logged. |
| Single WAF, prod | Set `master_secret`. Restarts don't invalidate outstanding cookies. |
| Multi-WAF, prod | Set the **same** `master_secret` *and* `key_rotation_interval` on every instance. Verification works without coordination; cookies issued by one instance validate on any other. |

For multi-instance, also make sure the WAFs' clocks are reasonably aligned —
the keyring tolerates one rotation interval of clock skew, no more.

### 3.5 Tuning checklist

- **Default-friendly** (low CPU, single-instance): no `challenge:` block, or
  just `master_secret` + `cookie_ttl`. Acceptable for most deployments.
- **High-traffic, wants per-visitor JS variance**: bump
  `crypto_obfuscation_pool_size` to 2–3. Costs `N × 5 s` of CPU per
  rotation.
- **Wants runtime library obfuscation** (against signature-based scrapers
  matching on the static bundle): set `library_runtime_obfuscation_enabled:
  true`, optionally raise `library_obfuscation_pool_size` to 2–3 so the
  refresher has room to grow. Costs ~1 min of CPU per
  `library_obfuscation_refresh_interval` (default 1 h) for one fresh
  variant per tick.
- **Long-lived cookies for known clients**: set a long `cookie_ttl`
  (24h, 7 days) — safe because cookie expiry is enforced by `not_after`,
  not by the much shorter keyring window.
- **Aggressive bot detection**: combine `EvaluateMismatches()` thresholds
  with atomic checks (`fingerprint.UAMobileMismatch`, etc.) and consider
  `SetChallengeDifficulty("high")` for suspect fingerprints. Reserve
  `"impossible"` for known-bad: solving it server-side is rejected, so it
  acts as a soft block via the challenge flow rather than a hard `ban`.

### 3.6 Operational notes

- The challenge runtime endpoints (`/crowdsec-internal/challenge/*`) are
  served on the same listener as the appsec acquisition module. They are
  not configurable independently.
- The default cookie name is `__crowdsec_challenge`. It is `HttpOnly`,
  `Path=/`, `SameSite=Lax`, and `Secure` when the request was HTTPS.
- Operator-issued allowlist cookies carry the reason string in their
  payload (≤ 256 bytes) — visible in logs and in the cookie value, **not**
  in the Set-Cookie attributes. Don't put secrets in the reason.
- The "impossible" difficulty produces a challenge page the client
  cannot solve. It functions as a soft block: visitors see a challenge
  loop instead of a 403, which is often the desired UX for ambiguous
  cases.

