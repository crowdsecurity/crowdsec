// obfuscator.go embeds the wasm build of `javascript-obfuscator` and exposes
// a single thread-safe entry point (ObfuscateJS) used by both the static and
// dynamic bundle paths. The compiled wazero module is shared across calls;
// each ObfuscateJS invocation instantiates a fresh module instance with its
// own stdin/stdout buffers so concurrent obfuscations don't collide.

package challenge

import (
	"bytes"
	"context"
	crand "crypto/rand"
	_ "embed"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
)

//go:embed js/obfuscate/index.wasm.gz
var obfuscatorWasmGz []byte

var (
	obfuscatorWasm     []byte
	obfuscatorWasmOnce sync.Once
)

// ObfuscateJS runs the input source through the embedded `javascript-obfuscator`
// wasm module and returns the obfuscated output. Thread-safe: wazero allows
// concurrent module instantiations from the same compiled module, which is
// what makes the dynamic-module singleflight pattern work.
func (c *ChallengeRuntime) ObfuscateJS(ctx context.Context, inputJS string) (string, error) {
	stdin := bytes.NewReader([]byte(inputJS))
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	config := wazero.NewModuleConfig().
		WithStdin(stdin).
		WithStdout(&stdout).
		WithStderr(&stderr).
		// Give wazero a real PRNG source and real wall/nano time so output is non-deterministic.
		WithRandSource(crand.Reader).
		WithSysWalltime().
		WithSysNanotime()

	mod, err := c.r.InstantiateModule(ctx, c.obfuscatorMod, config)
	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("wasm runtime error: %v | stderr: %s", err, stderr.String())
		}
		return "", fmt.Errorf("wasm instantiation error: %v", err)
	}

	mod.Close(ctx)

	return stdout.String(), nil
}
