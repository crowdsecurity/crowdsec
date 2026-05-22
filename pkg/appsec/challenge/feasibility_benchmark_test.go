//go:build feasibility

package challenge

// Step 0 feasibility benchmark for the split-bundle plan.
//
// Goals:
//   - Measure ObfuscateJS wall-clock cost on a small dynamic-module-shaped input
//     vs. the full challenge bundle, to validate the assumption that splitting
//     the bundle reduces obfuscation cost from ~1 minute to sub-second/few-second.
//   - Sanity-check that the existing WASM pipeline accepts a tiny input without
//     errors.
//
// Run with:
//   go test -v -run TestFeasibility -tags=feasibility ./pkg/appsec/challenge/
//   go test -v -bench BenchmarkObfuscate -benchtime=1x -tags=feasibility ./pkg/appsec/challenge/
//
// The build tag keeps these out of the normal CI run since each invocation
// takes tens of seconds to a minute.

import (
	"context"
	"testing"
	"time"
)

// dynamicModuleSample mimics the shape of the per-epoch dynamic module that
// the split-bundle plan introduces. ~30 lines of JS, contains a sentinel
// string for the `globalThis` hook lookup and a hex key literal.
const dynamicModuleSample = `(() => {
  const k = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const e = 1234567890;
  const hookName = "__CSEC_HOOK_4f3c0a9e__";

  function waitForHook(name, cb, attempts) {
    if (attempts === undefined) attempts = 200;
    if (typeof globalThis[name] === "function") {
      cb(globalThis[name]);
      return;
    }
    if (attempts <= 0) return;
    setTimeout(() => waitForHook(name, cb, attempts - 1), 10);
  }

  waitForHook(hookName, (hook) => {
    try {
      hook({ key: k, epoch: e });
    } catch (err) {
      console.error("challenge dynamic module: hook invocation failed", err);
    }
  });
})();
`

func newRuntimeForBench(tb testing.TB) *ChallengeRuntime {
	tb.Helper()
	ctx := context.Background()
	rt, err := NewChallengeRuntime(ctx)
	if err != nil {
		tb.Fatalf("NewChallengeRuntime: %v", err)
	}
	return rt
}

// TestFeasibilityDynamicModuleObfuscation runs ObfuscateJS once on the small
// dynamic-module-shaped input and reports the wall-clock cost.
func TestFeasibilityDynamicModuleObfuscation(t *testing.T) {
	rt := newRuntimeForBench(t)

	// Warm up the WASM runtime (first call pays init cost we don't want to count).
	warmStart := time.Now()
	_, err := rt.ObfuscateJS(context.Background(), `const x = 1;`)
	if err != nil {
		t.Fatalf("warmup ObfuscateJS: %v", err)
	}
	t.Logf("warmup obfuscation (1-line input):   %s", time.Since(warmStart))

	// Measured run: the realistic dynamic-module-shaped input.
	start := time.Now()
	out, err := rt.ObfuscateJS(context.Background(), dynamicModuleSample)
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("ObfuscateJS dynamic-module sample: %v", err)
	}
	t.Logf("dynamic-module-sample obfuscation:   %s", dur)
	t.Logf("input size:  %d bytes", len(dynamicModuleSample))
	t.Logf("output size: %d bytes", len(out))

	if len(out) == 0 {
		t.Fatalf("obfuscator returned empty output")
	}

	// Verdict per the plan:
	//   <1s   -> high-obfuscation viable for dynamic module (ideal)
	//   1-5s  -> still acceptable for "every few minutes" rotation
	//   >5s   -> downgrade to medium-obfuscation
	switch {
	case dur < time.Second:
		t.Logf("VERDICT: high-obfuscation viable for dynamic module (<1s)")
	case dur < 5*time.Second:
		t.Logf("VERDICT: high-obfuscation acceptable for dynamic module (1-5s)")
	default:
		t.Logf("VERDICT: high-obfuscation too slow for dynamic module (>5s); plan to downgrade to medium-obfuscation")
	}
}

// TestFeasibilityFullBundleObfuscation establishes the baseline cost — the full
// challenge bundle through the same pipeline. This is the ~1 minute we are
// trying to eliminate from the runtime path.
func TestFeasibilityFullBundleObfuscation(t *testing.T) {
	rt := newRuntimeForBench(t)
	bundle := rt.buildChallengeBundle()

	t.Logf("full bundle input size: %d bytes", len(bundle))

	start := time.Now()
	out, err := rt.ObfuscateJS(context.Background(), bundle)
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("ObfuscateJS full bundle: %v", err)
	}
	t.Logf("full-bundle obfuscation: %s", dur)
	t.Logf("output size: %d bytes", len(out))
}

// BenchmarkObfuscateDynamicModule runs the dynamic-module-shaped input
// repeatedly. Use -benchtime=Nx to control iteration count.
func BenchmarkObfuscateDynamicModule(b *testing.B) {
	rt := newRuntimeForBench(b)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rt.ObfuscateJS(ctx, dynamicModuleSample)
		if err != nil {
			b.Fatalf("ObfuscateJS: %v", err)
		}
	}
}
