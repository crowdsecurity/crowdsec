// Entry point for the fpscanner bundle: exposes the scanner on globalThis.
// Built by ./cmd/bundle into ./fpscanner.js (minified IIFE, served as-is).
import FingerprintScanner from "./fpscanner/src/index.ts";

globalThis.CrowdsecFingerprintScanner = FingerprintScanner;
