# Writing a custom detection script

A detection module is JavaScript distributed through the hub as a `challenge-js` data file. It
runs in the visitor's browser after fpscanner has collected the fingerprint, and can add its
own signals or correct fpscanner's verdicts. What it reports lands in `fingerprint.Custom` for
appsec-rules to score.

Every installed module is compiled separately and wrapped in its own scope, but they all share
one result object and one time budget. The rules below about `fp.custom` exist because breaking
them breaks a *different* module, silently.

## Writing a module

Export one function named `collectSignals`:

```js
export function collectSignals(fp) {
  fp.custom = fp.custom || {};
  fp.custom.myDetectorResult = true;
}
```

That is the whole contract. The engine compiles the file at startup and registers the export
for you — there is no hook list to append to.

`collectSignals` may return a promise; the runner awaits it.

### Rules for the file

- **Exactly one export, named `collectSignals`.** A file that exports nothing else is rejected,
  and so is one that exports something under a different name.
- **No `import`.** Relative paths, package names and `import("./x.js")` are all refused: the
  file has to be self-contained. Keep the whole detector, vendored dependencies included, in
  one file.
- **No top-level `await`.**
- **Target is ES2022.** Newer syntax is lowered where it can be; nothing is polyfilled.
- Top-level code runs once, when the script loads, before any hook is called.

Your top-level names are private to your file. Two modules can both declare `const CFG` or
`function measure()` without colliding — no IIFE wrapper and no name prefixes needed.

### When your module is rejected

A module that will not compile is named in the crowdsec log at error level, with the file, the
line and the reason, and is then dropped. **Every other module still loads.** So does the
challenge: if all of them are rejected, no custom script is served and detection falls back to
fpscanner alone.

The same isolation covers loading: if your top-level code throws, only your module fails to
register.

One gap worth knowing about — `import(someVariable)` and `require(someVariable)` cannot be
checked at compile time, so they pass the build and throw in the browser instead.

## Reporting results

Merge into `fp.custom`, never replace it:

```js
fp.custom = fp.custom || {};   // yes
fp.custom = { mine: true };    // no — drops every other module's keys
```

Namespace your keys with the detector's name (`realmFontDelta60`, `audioCtxNoise`). The object
is flat and shared.

Omit a key when you have no result rather than writing `null`. Both read as "no evidence" to a
rule, but the key you omit costs no cookie space.

Values must be a `boolean`, `string`, `number`, `string[]` or `number[]`. Objects, mixed arrays
and `null` decode as absent.

Nothing caps what you report, but the whole map has to fit whatever cookie space the
fingerprint leaves — on the order of 1kB. Overflow is not trimmed: the map is dropped whole,
with a warning naming the keys. Rules on the submission itself still see them; every later
request sees none. Report signals, not payloads.

## The time budget

All hooks share one deadline — `custom_js_timeout`, 500ms by default. It is total, not per
hook: whatever the hooks before yours spend, yours does not get. Hooks that do not finish are
cut, and their signals are simply absent.

Give any async work its own timeout comfortably under the budget, so a blocked path can report
*why* instead of being cut with no result at all. The realm-font detector runs its worker at
`timeoutMs: 350` against the 500ms default for exactly this reason.

A hook that throws, rejects or hangs is isolated — the others still run — but its own signal
is lost.

An operator adding several detectors should raise `custom_js_timeout` to match. It is time the
visitor spends watching a spinner, so raise it deliberately.

## Order, and overriding fpscanner

Hooks run in the order the modules were declared: `appsec_configs` order first, then `data:`
order within a config. Do not depend on it unless the composition is deliberate.

To correct an fpscanner verdict — a false positive on some browser build — set the detection
directly:

```js
fp.fastBotDetectionDetails.hasCDP.detected = false;
```

The runner recomputes the `fastBotDetection` summary flag afterwards, so clearing a detection
clears the summary too. `fsid` is deliberately *not* recomputed: it hashes the original
detection bitmask, and leaving it alone keeps ids comparable across deployments running
different scripts.

## Environment

The module runs on the protected site's origin under the challenge CSP, which allows
`blob:` workers. `OffscreenCanvas`, `fetch` and same-origin XHR are available.

## Scoring what you report

```yaml
name: myorg/appsec-bot-challenge-my-detector
data:
  - dest_file: challenge/my-detector.js
    type: challenge-js
inband:
  on_challenge_submit:
    - filter: 'fingerprint.Custom["myDetectorResult"].Bool'
      apply:
        - AddRequestScore(100, "my_detector")
```

Read values by kind: `.Bool`, `.Str`, `.Number`, `.Strings`, `.Floats`. An unset key returns
the zero value, so `fingerprint.Custom["never-set"].Bool` is `false` rather than an error —
filters need no presence check. Where "absent" and "present but false" must be told apart, use
`fingerprint.HasCustom("key")`.

The config must be listed **before** whichever config decides the outcome (the one calling
`RejectSubmission`), because that rejection halts every later `on_challenge_submit` rule.

## A worked example

`realm-font-mismatch.js` in the camoufox-vs-crowdsec repository detects font spoofing by
comparing text advance widths between the page and a worker. It shows the shape end to end: the
upstream detector inlined unchanged, a small adapter that exports `collectSignals`, an internal
timeout under the shared budget, namespaced keys, and a key omitted rather than nulled when the
run is inconclusive.
