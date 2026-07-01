// This package contains all JavaScript-related code for the WAF challenge and fingerprinting.
// fpscanner is https://github.com/antoinevastel/fpscanner/
// obfuscate is a custom wrapper around javascript-obfuscator.
// It uses a vendored bundle of javascript-obfuscator to avoid any dependency on npm at build time.
// The goal is to build a WASM module that can dynamically obfuscate the challenge code at runtime.
//
// The client JS is split into two bundles (built by ./cmd/bundle):
//   - FPScannerJS:  the public fingerprint scanner, served UNOBFUSCATED via its
//     own <script src> tag (cacheable across challenge pages).
//   - ChallengeCode: the crypto/glue, obfuscated at build time (./cmd/initialbundle)
//     into ../initial_bundle.js.gz and injected inline on the challenge page.

package js

import _ "embed"

// FPScannerJS is the standalone, unobfuscated fpscanner bundle served as-is.
//
//go:embed fpscanner/fpscanner.js
var FPScannerJS string

// ChallengeCode is the minified (not-yet-obfuscated) challenge crypto/glue code.
// It still carries the __CROWDSEC_*_PATH__ placeholders; the runtime substitutes
// them before obfuscation (see buildChallengeBundle in static_bundle.go).
//
//go:embed challenge_code.js
var ChallengeCode string
