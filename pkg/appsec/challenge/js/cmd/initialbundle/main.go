// initialbundle is a build-time tool that produces a pre-obfuscated initial
// challenge bundle, embedded into the Go binary. This eliminates the ~1 minute
// of synchronous obfuscation that NewChallengeRuntime would otherwise have to
// pay at startup before the service is ready to serve challenges.
//
// Pipeline:
//
//   fpscanner/bundle.js  ──substitute placeholders──▶  source JS
//   obfuscate/index.wasm.gz ──decompress──▶ obfuscator WASM
//   wazero(obfuscator).Run(stdin=source) ──▶ obfuscated JS
//   gzip ──▶ ../initial_bundle.js.gz
//
// The output `initial_bundle.js.gz` is committed and embedded via go:embed in
// pkg/appsec/challenge/challenge.go.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// These must match the ChallengeSubmitPath / ChallengePowWorkerPath constants
// in pkg/appsec/challenge/challenge.go. Kept as plain strings here to avoid an
// import cycle (pkg/appsec/challenge depends on this js subpackage).
const (
	submitPath    = "/crowdsec-internal/challenge/submit"
	powWorkerPath = "/crowdsec-internal/challenge/pow-worker.js"
)

const (
	// Inputs (relative to pkg/appsec/challenge/js where this tool runs).
	fpscannerBundlePath = "fpscanner/bundle.js"
	obfuscatorWasmGz    = "obfuscate/index.wasm.gz"
	// Output (relative to pkg/appsec/challenge/js).
	outputPath = "../initial_bundle.js.gz"
)

func main() {
	start := time.Now()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "initialbundle: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "initialbundle: wrote %s in %s\n", outputPath, time.Since(start).Round(time.Second))
}

func run() error {
	source, err := buildSourceBundle()
	if err != nil {
		return fmt.Errorf("build source bundle: %w", err)
	}

	wasmBytes, err := loadObfuscatorWasm()
	if err != nil {
		return fmt.Errorf("load obfuscator wasm: %w", err)
	}

	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		return fmt.Errorf("instantiate wasi: %w", err)
	}

	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("compile obfuscator wasm: %w", err)
	}

	obfuscated, err := obfuscate(ctx, r, compiled, source)
	if err != nil {
		return fmt.Errorf("obfuscate: %w", err)
	}

	if len(obfuscated) == 0 {
		return fmt.Errorf("obfuscator produced empty output")
	}

	if err := writeGzip(outputPath, obfuscated); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}

	fmt.Fprintf(os.Stderr, "initialbundle: input %d bytes -> obfuscated %d bytes -> compressed file written\n",
		len(source), len(obfuscated))

	return nil
}

func buildSourceBundle() (string, error) {
	raw, err := os.ReadFile(fpscannerBundlePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fpscannerBundlePath, err)
	}

	// Same substitution as ChallengeRuntime.buildChallengeBundle in challenge.go.
	source := strings.NewReplacer(
		"__CROWDSEC_SUBMIT_PATH__", submitPath,
		"__CROWDSEC_POW_WORKER_PATH__", powWorkerPath,
	).Replace(string(raw))

	return source, nil
}

func loadObfuscatorWasm() ([]byte, error) {
	f, err := os.Open(obfuscatorWasmGz)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	return io.ReadAll(gz)
}

func obfuscate(ctx context.Context, r wazero.Runtime, compiled wazero.CompiledModule, source string) (string, error) {
	stdin := bytes.NewReader([]byte(source))
	var stdout, stderr bytes.Buffer

	cfg := wazero.NewModuleConfig().
		WithStdin(stdin).
		WithStdout(&stdout).
		WithStderr(&stderr)

	mod, err := r.InstantiateModule(ctx, compiled, cfg)
	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("wasm runtime error: %v | stderr: %s", err, stderr.String())
		}
		return "", fmt.Errorf("wasm instantiation: %w", err)
	}
	mod.Close(ctx)

	return stdout.String(), nil
}

func writeGzip(path string, data string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("gzip writer: %w", err)
	}
	zw.Name = "initial_bundle.js"
	zw.ModTime = time.Unix(0, 0)

	if _, err := zw.Write([]byte(data)); err != nil {
		zw.Close()
		return err
	}

	return zw.Close()
}
