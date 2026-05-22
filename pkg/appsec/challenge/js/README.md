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
| `cmd/bundle` | esbuild (Go module) | `fpscanner/bundle.js` | The runtime obfuscator (input) |
| `cmd/obfuscate` | esbuild + `javy` | `obfuscate/index.wasm.gz` | `wazero` to obfuscate the dynamic key module per epoch |
| `cmd/initialbundle` | `wazero` running the obfuscator wasm | `../initial_bundle.js.gz` | Seeded into the challenge cache at startup so the service is ready in seconds, not minutes |

`fpscanner/bundle.js` is itself a transformed copy of `../challenge.js`
plus the `fpscanner/src/*` TypeScript sources, bundled to a single
ES2022 module by esbuild.

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

The full regeneration takes about a minute on a modern laptop because
the obfuscator's `high-obfuscation` preset runs heavy
control-flow-flattening + string-array transforms over the ~37 KB
fpscanner bundle.

## When to regenerate

Run `make generate-challenge-js` after changing any of:

- `pkg/appsec/challenge/challenge.js`
- `pkg/appsec/challenge/dynamic_module.js.tmpl`
- `pkg/appsec/challenge/js/fpscanner/src/**/*.ts`
- `pkg/appsec/challenge/js/obfuscate/obfuscate.js`
- The vendored `pkg/appsec/challenge/js/obfuscate/javascript-obfuscator.js`
  (only when intentionally upgrading)

The pipeline output bytes (`bundle.js`, `index.wasm.gz`,
`initial_bundle.js.gz`) are committed so a clean `git clone` builds and
runs without javy.

## Sentinel survival

The `__CSEC_CHALLENGE_HOOK_v1__` literal must appear verbatim in both
the static bundle (`initial_bundle.js.gz`) and any dynamic key module
generated at runtime, so the two bundles meet at the same `globalThis`
key after independent obfuscation passes. The
`reservedStrings: ["__CSEC_CHALLENGE_HOOK_v1__"]` option in
`obfuscate/obfuscate.js` is what guarantees this. If you change the
sentinel string, change it in **all three** places:

- `obfuscate/obfuscate.js` — `reservedStrings`
- `pkg/appsec/challenge/challenge.js` — `CSEC_HOOK_NAME`
- `pkg/appsec/challenge/dynamic_module.js.tmpl` — `hookName`

The Go-side regression test
`TestSplitBundle_HookSentinelInBakedBundle` will fire on a mismatch.
