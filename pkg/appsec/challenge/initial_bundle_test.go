package challenge

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	challengejs "github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/js"
)

// TestNewChallengeRuntimeStartupBudget ensures NewChallengeRuntime returns
// quickly (seeded from the baked-in bundle), without paying the synchronous
// obfuscation it would otherwise pay.
func TestNewChallengeRuntimeStartupBudget(t *testing.T) {
	const budget = 10 * time.Second

	start := time.Now()
	rt, err := NewChallengeRuntime(t.Context())
	dur := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, rt)
	t.Logf("NewChallengeRuntime returned in %s", dur)

	if dur > budget {
		t.Fatalf("NewChallengeRuntime took %s, exceeds budget of %s; baked-in initial bundle should make this near-instant", dur, budget)
	}

	// The challenge code must be loaded so the very first request can be served.
	require.NotEmpty(t, rt.getChallengeCode(), "challenge code should be seeded from the baked-in initial bundle")
}

// TestSeedCacheFromInitialBundle directly exercises the seeding helper and
// asserts the bundle decompresses to non-empty obfuscated JS that holds the
// challenge crypto code — and crucially NOT the public fpscanner (which is now
// served separately and unobfuscated).
func TestSeedCacheFromInitialBundle(t *testing.T) {
	rt := &ChallengeRuntime{}

	require.NoError(t, rt.seedCacheFromInitialBundle())

	code := rt.getChallengeCode()
	require.NotEmpty(t, code)

	// The obfuscated challenge code inflates well beyond its tiny source.
	t.Logf("seeded challenge code size: %d bytes", len(code))
	require.Greater(t, len(code), 50_000,
		"seeded challenge code is suspiciously small; was it actually obfuscated?")

	// Path placeholders must have been substituted before obfuscation.
	require.NotContains(t, code, "__CROWDSEC_SUBMIT_PATH__",
		"submit path placeholder still present; substitution missed at build time")
	require.NotContains(t, code, "__CROWDSEC_POW_WORKER_PATH__",
		"pow worker path placeholder still present; substitution missed at build time")

	// The fpscanner sources must NOT be baked into the obfuscated challenge
	// code anymore — they live in the separately-served fpscanner bundle.
	// fpscanner-only detection strings are a reliable tell.
	require.NotContains(t, strings.ToLower(code), "swiftshader",
		"fpscanner code leaked into the obfuscated challenge bundle (it should be served separately)")
	require.NotContains(t, strings.ToLower(code), "playwright",
		"fpscanner code leaked into the obfuscated challenge bundle (it should be served separately)")
}

// TestFPScannerBundleServedRaw asserts the public fpscanner bundle is the
// unobfuscated, separately-served asset: it exposes the scanner on globalThis
// and still contains the readable fpscanner detection logic.
func TestFPScannerBundleServedRaw(t *testing.T) {
	require.NotEmpty(t, challengejs.FPScannerJS)
	require.Equal(t, challengejs.FPScannerJS, FPScannerJS,
		"challenge.FPScannerJS must re-export the js subpackage bundle verbatim")

	require.Contains(t, FPScannerJS, "globalThis.CrowdsecFingerprintScanner",
		"served fpscanner bundle must expose the scanner on globalThis for the challenge code")
	require.Contains(t, strings.ToLower(FPScannerJS), "playwright",
		"served fpscanner bundle is minified but NOT obfuscated; detection strings should remain readable")
}
