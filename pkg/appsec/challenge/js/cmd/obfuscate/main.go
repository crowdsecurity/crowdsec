package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
	bundleData, err := buildObfuscatorBundle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build obfuscator bundle: %v\n", err)
		os.Exit(1)
	}

	// javy output is not byte-reproducible, so rebuilding from unchanged
	// sources would always dirty index.wasm.gz. The inputs (bundle content,
	// javy version) are recorded in the gzip header comment; skip the rebuild
	// when they match the existing file.
	buildKey, err := computeBuildKey(bundleData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to compute build key: %v\n", err)
		os.Exit(1)
	}

	if currentBuildKey() == buildKey {
		fmt.Fprintf(os.Stderr, "obfuscate: %s is up to date, skipping javy build\n", wasmGzFile)
		return
	}

	if err := os.WriteFile(bundleFile, bundleData, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", bundleFile, err)
		os.Exit(1)
	}

	if err := buildWASM(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build obfuscator wasm: %v\n", err)
		os.Exit(1)
	}

	if err := gzipWASM(buildKey); err != nil {
		fmt.Fprintf(os.Stderr, "failed to compress obfuscator wasm: %v\n", err)
		os.Exit(1)
	}
}

func buildObfuscatorBundle() ([]byte, error) {
	result := esbuildapi.Build(esbuildapi.BuildOptions{
		EntryPoints: []string{entryPoint},
		Bundle:      true,
		Write:       false,
		Format:      esbuildapi.FormatIIFE,
		Platform:    esbuildapi.PlatformBrowser,
		Target:      esbuildapi.ES2022,
		Sourcemap:   esbuildapi.SourceMapNone,
		// JS obfuscator expects window/global to be available, but in WASM we don't have them, so we alias them to globalThis
		Banner: map[string]string{"js": "var self=globalThis; var window=globalThis; var global=globalThis;"},
	})

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("esbuild failed with %d error(s): %s", len(result.Errors), result.Errors[0].Text)
	}
	if len(result.OutputFiles) == 0 {
		return nil, errors.New("esbuild returned no output files")
	}

	return result.OutputFiles[0].Contents, nil
}

func computeBuildKey(bundleData []byte) (string, error) {
	out, err := exec.CommandContext(context.Background(), "javy", "--version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run 'javy --version' (is javy in PATH?): %w", err)
	}

	return fmt.Sprintf("bundle-sha256=%x %s", sha256.Sum256(bundleData), strings.TrimSpace(string(out))), nil
}

// currentBuildKey returns the build key recorded in the existing wasm.gz
// header, or "" if the file is missing or unreadable.
func currentBuildKey() string {
	f, err := os.Open(wasmGzFile)
	if err != nil {
		return ""
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return ""
	}
	defer zr.Close()

	return zr.Comment
}

func buildWASM() error {
	cmd := exec.CommandContext(context.Background(), "javy", "build", "-o", wasmFile, bundleFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("javy build failed: %w", err)
	}

	return nil
}

func gzipWASM(buildKey string) error {
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
	zw.Comment = buildKey

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
