// This package contains all JavaScript-related code for the WAF challenge and fingerprinting.
// fpscanner is https://github.com/antoinevastel/fpscanner/
// obfuscate is a custom wrapper around javascript-obfuscator.
// It uses a vendored bundle of javascript-obfuscator to avoid any dependency on npm at build time.
// The goal is to build a WASM module that can dynamically obfuscate the challenge code at runtime.
// We bundle fpscanner and our custom fingerprinting code together; the resulting bundle is embedded in the binary.

package js

import _ "embed"

//go:embed fpscanner/bundle.js
var FPScannerBundle string
