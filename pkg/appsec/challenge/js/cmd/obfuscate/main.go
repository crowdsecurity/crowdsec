package main

import (
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"time"

	esbuildapi "github.com/evanw/esbuild/pkg/api"
)

const (
	entryPoint = "obfuscate/obfuscate.js"
	bundleFile = "obfuscate/bundle.js"
	wasmFile   = "obfuscate/index.wasm"
	wasmGzFile = "obfuscate/index.wasm.gz"
)

func main() {
	if err := buildObfuscatorBundle(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build obfuscator bundle: %v\n", err)
		os.Exit(1)
	}

	if err := buildWASM(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build obfuscator wasm: %v\n", err)
		os.Exit(1)
	}

	if err := gzipWASM(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to compress obfuscator wasm: %v\n", err)
		os.Exit(1)
	}
}

func buildObfuscatorBundle() error {
	result := esbuildapi.Build(esbuildapi.BuildOptions{
		EntryPoints: []string{entryPoint},
		Bundle:      true,
		Write:       false,
		Format:      esbuildapi.FormatIIFE,
		Platform:    esbuildapi.PlatformBrowser,
		Target:      esbuildapi.ES2022,
		Sourcemap:   esbuildapi.SourceMapNone,
		Banner:      map[string]string{"js": "var self=globalThis; var window=globalThis; var global=globalThis;"}, // JS obfuscator expects to have this available, but in WASM we don't have a window or global object, so we alias them to globalThis
	})

	if len(result.Errors) > 0 {
		return fmt.Errorf("esbuild failed with %d error(s): %s", len(result.Errors), result.Errors[0].Text)
	}
	if len(result.OutputFiles) == 0 {
		return fmt.Errorf("esbuild returned no output files")
	}

	return os.WriteFile(bundleFile, result.OutputFiles[0].Contents, 0o644)
}

func buildWASM() error {
	if _, err := exec.LookPath("javy"); err != nil {
		return fmt.Errorf("javy was not found in PATH")
	}

	cmd := exec.Command("javy", "build", "-o", wasmFile, bundleFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("javy build failed: %w", err)
	}

	return nil
}

func gzipWASM() error {
	wasmData, err := os.ReadFile(wasmFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", wasmFile, err)
	}

	f, err := os.Create(wasmGzFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", wasmGzFile, err)
	}
	defer f.Close()

	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("failed to create gzip writer: %w", err)
	}
	zw.Name = "index.wasm"
	zw.ModTime = time.Unix(0, 0)

	if _, err := zw.Write(wasmData); err != nil {
		zw.Close()
		return fmt.Errorf("failed to write gzip data: %w", err)
	}

	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	os.Remove(wasmFile)
	os.Remove(bundleFile)

	return nil
}
