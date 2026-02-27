// This package contain all Javascript related code for challenge/fingerprinting by the WAF.
// fpscanner is https://github.com/antoinevastel/fpscanner/
// obfuscate is a custom wrapper around javascript obfuscator.
// It uses a vendored bundle of javascript-obfuscator to avoir any dependancy on npm at build time.
// The goal is to build a WASM module that can be used to dynamically obfuscate the challenge code at runtime.
// We bundle both fpscanner and our custom fingerprinting code together, and this bundle is what is ob

package js

import _ "embed"

//go:embed fpscanner/bundle.js
var FPScannerBundle string
