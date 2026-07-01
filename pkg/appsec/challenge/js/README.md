# WAF challenge JS pipeline

This directory holds the JavaScript sources that the WAF challenge runtime
serves to clients, and the build-time tools that turn them into the
artifacts embedded in the crowdsec binary.

End users running `make build` do **not** need any of the tools below —
the generated artifacts are committed to the repository and pulled in via
`//go:embed`. The pipeline is only exercised when someone intentionally
changes the JS sources.

## What gets generated

Three pipeline steps, all driven by `go:generate` directives in
`generate.go`:

| Step | Tool used | Output | Used at runtime by |
|---|---|---|---|
| `cmd/bundle` | esbuild (Go module) | `fpscanner/fpscanner.js` **and** `challenge_code.js` | `fpscanner.js` is served as-is; `challenge_code.js` is the obfuscator input |
| `cmd/obfuscate` | esbuild + `javy` | `obfuscate/index.wasm.gz` | `wazero` to obfuscate the dynamic key module per epoch |
| `cmd/initialbundle` | `wazero` running the obfuscator wasm | `../initial_bundle.js.gz` | Seeded into the challenge cache at startup so the service is ready instantly |

The client JS is split into **two** bundles:

- **`fpscanner/fpscanner.js`** — the public fingerprint scanner
  (`fpscanner/src/*`, entered via `fpscanner/global.js`), built as a minified
  IIFE that assigns `globalThis.CrowdsecFingerprintScanner`. It is **served
  unobfuscated** at `ChallengeFPScannerPath` via a plain `<script src>` tag
  (cacheable across challenge pages). fpscanner is public open-source code, so
  there is nothing to hide and no reason to spend CPU obfuscating it.
- **`challenge_code.js`** — the crypto/glue (`../challenge.js`: SHA-256, HMAC,
  PoW, fingerprint obfuscation, submission, and the hook registration). This is
  the **obfuscation input**: `cmd/initialbundle` substitutes the internal-path
  placeholders and obfuscates it into `../initial_bundle.js.gz`, which the
  runtime injects inline on the challenge page. The challenge code reads the
  scanner from `globalThis.CrowdsecFingerprintScanner` at use time.

There is no runtime re-obfuscation of the challenge code — the build-time
`initial_bundle.js.gz` is the single static variant served. Only the sensitive
per-epoch key module is re-obfuscated at runtime (see `../dynamic_module.go`).

`obfuscate/obfuscate.js` is a small driver around the vendored
`obfuscate/javascript-obfuscator.js` (≈1.6 MB, kept in tree so we don't
pull from npm at build time). The driver reads source code from stdin,
runs `JavaScriptObfuscator.obfuscate(...)` with the `high-obfuscation`
preset (plus a `reservedStrings` entry for the `__CSEC_CHALLENGE_HOOK_v1__`
sentinel that bridges the static and dynamic bundles), and writes the
obfuscated code to stdout. `javy` then compiles that driver to a WASM
module.

## How to regenerate

```sh
make generate-challenge-js
```

Or directly:

```sh
go generate ./pkg/appsec/challenge/js/...
```

Both invocations require `javy` (the Bytecode Alliance JS-to-WASM
compiler) to be on `PATH`. There is no apt/brew package; install via
the upstream releases:

```sh
curl -sL -o javy.gz \
  https://github.com/bytecodealliance/javy/releases/download/v8.1.1/javy-x86_64-linux-v8.1.1.gz
gunzip javy.gz && chmod +x javy && mv javy /usr/local/bin/
```

(Substitute the platform suffix for macOS/Windows.) `javy` is
**build-time only** — it is not a runtime dependency of crowdsec.

Regeneration is fast now: only the small `challenge_code.js` (~4 KB) goes
through the obfuscator's `high-obfuscation` preset; the bulk of the client
JS (fpscanner, ~33 KB) is served raw and is never obfuscated.

> `javy` is only needed by `cmd/obfuscate` (it rebuilds `index.wasm.gz`). If
> you only changed `challenge.js` or the fpscanner sources, you can skip javy
> and regenerate just the two bundles:
>
> ```sh
> cd pkg/appsec/challenge/js && go run ./cmd/bundle && go run ./cmd/initialbundle
> ```

## When to regenerate

Run `make generate-challenge-js` (or the two-step command above) after
changing any of:

- `pkg/appsec/challenge/challenge.js`
- `pkg/appsec/challenge/dynamic_module.js.tmpl`
- `pkg/appsec/challenge/js/fpscanner/global.js`
- `pkg/appsec/challenge/js/fpscanner/src/**/*.ts`
- `pkg/appsec/challenge/js/obfuscate/obfuscate.js`
- The vendored `pkg/appsec/challenge/js/obfuscate/javascript-obfuscator.js`
  (only when intentionally upgrading)

The pipeline output bytes (`fpscanner/fpscanner.js`, `challenge_code.js`,
`index.wasm.gz`, `initial_bundle.js.gz`) are committed so a clean `git clone`
builds and runs without javy.

## Sentinel survival

The `__CSEC_CHALLENGE_HOOK_v1__` literal must appear verbatim in both
the obfuscated challenge code (`initial_bundle.js.gz`) and any dynamic key
module generated at runtime, so the two bundles meet at the same `globalThis`
key after independent obfuscation passes. The
`reservedStrings: ["__CSEC_CHALLENGE_HOOK_v1__"]` option in
`obfuscate/obfuscate.js` is what guarantees this. If you change the
sentinel string, change it in **all three** places:

- `obfuscate/obfuscate.js` — `reservedStrings`
- `pkg/appsec/challenge/challenge.js` — `CSEC_HOOK_NAME`
- `pkg/appsec/challenge/dynamic_module.js.tmpl` — `hookName`

The Go-side regression test
`TestSplitBundle_HookSentinelInBakedBundle` will fire on a mismatch.
