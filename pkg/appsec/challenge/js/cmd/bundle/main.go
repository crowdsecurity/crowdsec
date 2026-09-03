package main

import (
	"errors"
	"fmt"
	"os"

	esbuildapi "github.com/evanw/esbuild/pkg/api"
)

// The challenge JS is shipped as two separate bundles:
//
//   - fpscanner.js  — the public fingerprint scanner, served UNOBFUSCATED via a
//     plain <script src> tag (cacheable). Built as a minified IIFE that assigns
//     globalThis.CrowdsecFingerprintScanner (see fpscanner/global.js).
//   - challenge_code.js — the crypto/glue (SHA-256, HMAC, PoW, submission, hook
//     registration). This is the obfuscation input consumed by ./cmd/initialbundle.
type bundleTarget struct {
	entryPoint string
	outFile    string
	format     esbuildapi.Format
}

var targets = []bundleTarget{
	{entryPoint: "fpscanner/global.js", outFile: "fpscanner/fpscanner.js", format: esbuildapi.FormatIIFE},
	{entryPoint: "../challenge.js", outFile: "challenge_code.js", format: esbuildapi.FormatESModule},
}

func main() {
	for _, t := range targets {
		if err := build(t); err != nil {
			fmt.Fprintf(os.Stderr, "bundle %s: %v\n", t.outFile, err)
			os.Exit(1)
		}
	}
}

func build(t bundleTarget) error {
	result := esbuildapi.Build(esbuildapi.BuildOptions{
		EntryPoints:       []string{t.entryPoint},
		Bundle:            true,
		Write:             false,
		Format:            t.format,
		Platform:          esbuildapi.PlatformBrowser,
		Target:            esbuildapi.ES2022,
		MinifyWhitespace:  true,
		MinifyIdentifiers: true,
		MinifySyntax:      true,
		Sourcemap:         esbuildapi.SourceMapNone,
	})

	if len(result.Errors) > 0 {
		for _, msg := range result.Errors {
			fmt.Fprintln(os.Stderr, msg.Text)
		}
		return fmt.Errorf("esbuild failed with %d error(s)", len(result.Errors))
	}

	if len(result.OutputFiles) == 0 {
		return errors.New("esbuild returned no output files")
	}

	if err := os.WriteFile(t.outFile, result.OutputFiles[0].Contents, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", t.outFile, err)
	}

	return nil
}
