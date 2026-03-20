package main

import (
	"fmt"
	"os"

	esbuildapi "github.com/evanw/esbuild/pkg/api"
)

const (
	entryPoint = "../challenge.js"
	outFile    = "fpscanner/bundle.js"
)

func main() {
	result := esbuildapi.Build(esbuildapi.BuildOptions{
		EntryPoints:       []string{entryPoint},
		Bundle:            true,
		Write:             false,
		Format:            esbuildapi.FormatESModule,
		Platform:          esbuildapi.PlatformBrowser,
		Target:            esbuildapi.ES2022,
		MinifyWhitespace:  true,
		MinifyIdentifiers: true,
		MinifySyntax:      true,
		Sourcemap:         esbuildapi.SourceMapNone,
	})

	if len(result.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "esbuild failed with %d error(s)\n", len(result.Errors))
		for _, msg := range result.Errors {
			fmt.Fprintln(os.Stderr, msg.Text)
		}
		os.Exit(1)
	}

	if len(result.OutputFiles) == 0 {
		fmt.Fprintln(os.Stderr, "esbuild returned no output files")
		os.Exit(1)
	}

	if err := os.WriteFile(outFile, result.OutputFiles[0].Contents, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", outFile, err)
		os.Exit(1)
	}
}
