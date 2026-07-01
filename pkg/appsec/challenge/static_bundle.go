// Package challenge static_bundle.go handles the **challenge code** — the
// crypto/glue JavaScript injected inline on the challenge page. It is obfuscated
// once at build time (initial_bundle.js.gz) and loaded verbatim at startup; no
// runtime re-obfuscation. The public fpscanner is served separately and
// unobfuscated at ChallengeFPScannerPath. For the sensitive per-epoch HMAC sign
// key, see dynamic_module.go.
package challenge

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	challengejs "github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/js"
	log "github.com/sirupsen/logrus"
)

// initialBundleGz is the build-time obfuscated challenge code (via
// `go generate ./pkg/appsec/challenge/js/...`), embedded so the runtime can
// serve it immediately without paying the obfuscation cost at startup.
//
//go:embed initial_bundle.js.gz
var initialBundleGz []byte

var (
	initialBundle     string
	initialBundleOnce sync.Once
	initialBundleErr  error
)

// FPScannerJS is the public, unobfuscated fpscanner bundle served at
// ChallengeFPScannerPath. Re-exported so the dispatcher can serve it via the
// challenge package alongside PowWorkerJS.
var FPScannerJS = challengejs.FPScannerJS

// seedCacheFromInitialBundle decompresses the build-time obfuscated challenge
// code (initial_bundle.js.gz) and stores it as the static code served on every
// challenge page. Cheap (~ms) — eliminates the obfuscation that startup would
// otherwise pay.
func (c *ChallengeRuntime) seedCacheFromInitialBundle() error {
	initialBundleOnce.Do(func() {
		decompressStart := time.Now()

		if len(initialBundleGz) == 0 {
			initialBundleErr = errors.New("baked-in initial_bundle.js.gz is empty (was `go generate` run?)")
			return
		}

		gz, err := gzip.NewReader(bytes.NewReader(initialBundleGz))
		if err != nil {
			initialBundleErr = fmt.Errorf("gzip reader for initial bundle: %w", err)
			return
		}
		defer gz.Close()

		decoded, err := io.ReadAll(gz)
		if err != nil {
			initialBundleErr = fmt.Errorf("decompress initial bundle: %w", err)
			return
		}
		initialBundle = string(decoded)

		c.log().WithFields(log.Fields{
			"compressed_bytes":   len(initialBundleGz),
			"decompressed_bytes": len(initialBundle),
			"duration_ms":        time.Since(decompressStart).Milliseconds(),
		}).Debug("decompressed baked-in obfuscated challenge code")
	})

	if initialBundleErr != nil {
		return initialBundleErr
	}
	if initialBundle == "" {
		return errors.New("initial bundle is empty after decompression")
	}

	c.challengeCode = initialBundle

	return nil
}

// buildChallengeBundle substitutes the internal-path placeholders into the
// (minified, not-yet-obfuscated) challenge code. Used only by the synchronous
// fallback below — the normal path serves the pre-obfuscated initial bundle.
func (*ChallengeRuntime) buildChallengeBundle() string {
	return strings.NewReplacer(
		"__CROWDSEC_SUBMIT_PATH__", ChallengeSubmitPath,
		"__CROWDSEC_POW_WORKER_PATH__", ChallengePowWorkerPath,
	).Replace(challengejs.ChallengeCode)
}

// generateAndCacheChallengeJS is the synchronous fallback used when the
// baked-in initial bundle is missing or corrupt at startup. It obfuscates the
// challenge code in the foreground — undesirable but preferable to starting up
// with no code to serve when `go generate` was not run. Steady-state operation
// never hits this path.
func (c *ChallengeRuntime) generateAndCacheChallengeJS(ctx context.Context) error {
	obfuscated, err := c.ObfuscateJS(ctx, c.buildChallengeBundle())
	if err != nil {
		return err
	}

	c.challengeCode = obfuscated

	return nil
}

// getChallengeCode returns the static, build-time-obfuscated challenge code
// injected inline on the challenge page.
func (c *ChallengeRuntime) getChallengeCode() string {
	return c.challengeCode
}
