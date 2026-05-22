// Package challenge static_bundle.go handles the **library bundle** —
// the public, non-sensitive JavaScript shipped to the visitor (fpscanner,
// PoW worker glue, IndexedDB persistence, fetch handlers). The source
// lives in pkg/appsec/challenge/js/fpscanner/bundle.js and is freely
// readable in the open-source repo, so obfuscation here is not
// protecting a secret — it only buys per-visitor byte variance against
// naive signature-based scrapers.
//
// At startup the pool is seeded with `initial_bundle.js.gz`, a variant
// produced at build time via `go generate`. Runtime re-obfuscation of
// this bundle is **opt-in** via WithLibraryRuntimeObfuscationEnabled
// because each pass costs ~1 minute of CPU; when enabled, the refresher
// trickles in one new variant per tick (oldest evicted) so steady-state
// cost is bounded to a single obfuscation per
// WithLibraryObfuscationRefreshInterval.
//
// For the **sensitive** path (per-epoch HMAC sign key), see
// dynamic_module.go.
package challenge

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	challengejs "github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/js"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// initialBundleGz is a pre-obfuscated library bundle produced at build time
// by `go generate ./pkg/appsec/challenge/js/...`. It seeds the library
// bundle pool at startup so the service is immediately ready to serve
// challenges without waiting ~1 minute for the first variant to be
// obfuscated synchronously. When library obfuscation is enabled, the
// background refresher continues to add fresh runtime-generated variants
// at the configured cadence.
//
//go:embed initial_bundle.js.gz
var initialBundleGz []byte

var (
	initialBundle     string
	initialBundleOnce sync.Once
	initialBundleErr  error
)

type obfuscatedScript struct {
	Code string    // the obfuscated JS code
	uuid uuid.UUID // unique ID to track the script
}

// seedCacheFromInitialBundle decompresses the build-time obfuscated bundle
// (initial_bundle.js.gz) and inserts it into the library bundle pool as
// the first variant. Cheap (~ms) — eliminates the ~1 minute synchronous
// obfuscation that startup would otherwise pay.
func (c *ChallengeRuntime) seedCacheFromInitialBundle() error {
	initialBundleOnce.Do(func() {
		decompressStart := time.Now()

		if len(initialBundleGz) == 0 {
			initialBundleErr = fmt.Errorf("baked-in initial_bundle.js.gz is empty (was `go generate` run?)")
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

		log.WithFields(log.Fields{
			"compressed_bytes":   len(initialBundleGz),
			"decompressed_bytes": len(initialBundle),
			"duration_ms":        time.Since(decompressStart).Milliseconds(),
		}).Info("WAF challenge: decompressed baked-in obfuscated initial bundle")
	})

	if initialBundleErr != nil {
		return initialBundleErr
	}
	if initialBundle == "" {
		return fmt.Errorf("initial bundle is empty after decompression")
	}

	c.appendLibraryBundle([]obfuscatedScript{{
		Code: initialBundle,
		uuid: uuid.New(),
	}})

	return nil
}

// libraryBundlePoolRefresher is the background goroutine that trickles
// new obfuscated library-bundle variants into the pool on the configured
// refresh interval. Spawned only when WithLibraryRuntimeObfuscationEnabled
// is set (default off) — when disabled, the runtime serves only the
// baked-in initial bundle and pays no runtime obfuscator cost.
//
// Each tick generates exactly one new variant (~1 minute of CPU) and
// appends it; appendLibraryBundle's trim caps total pool size at
// libraryPoolSize, evicting the oldest entry. Full pool rotation
// therefore takes libraryPoolSize × refreshInterval.
func (c *ChallengeRuntime) libraryBundlePoolRefresher(ctx context.Context) {
	ticker := time.NewTicker(c.libraryRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			variants, err := c.generateLibraryBundleVariants(ctx, 1)
			if err != nil {
				log.Errorf("failed to refresh library bundle pool: %v", err)
				continue
			}

			c.appendLibraryBundle(variants)
		case <-ctx.Done():
			return
		}
	}
}

func (c *ChallengeRuntime) buildChallengeBundle() string {
	return strings.NewReplacer(
		"__CROWDSEC_SUBMIT_PATH__", ChallengeSubmitPath,
		"__CROWDSEC_POW_WORKER_PATH__", ChallengePowWorkerPath,
	).Replace(challengejs.FPScannerBundle)
}

// generateAndCacheChallengeJS is the synchronous fallback used when the
// baked-in initial bundle is missing or corrupt at startup. It pays the
// ~1 minute obfuscation cost in the foreground — undesirable but
// preferable to starting up with an empty pool when `go generate` was
// not run. Steady-state operation never hits this path.
func (c *ChallengeRuntime) generateAndCacheChallengeJS(ctx context.Context) error {
	variants, err := c.generateLibraryBundleVariants(ctx, 1)
	if err != nil {
		return err
	}

	c.appendLibraryBundle(variants)

	return nil
}

// generateLibraryBundleVariants runs the obfuscator `count` times on the
// library bundle and returns the resulting variants. Each obfuscation is
// the expensive (~1 minute) full-bundle pass — callers should generally
// pass count=1 and rely on the trickle pattern to grow the pool over
// time. The exception is the synchronous fallback path used when the
// baked-in bundle is unavailable.
func (c *ChallengeRuntime) generateLibraryBundleVariants(ctx context.Context, count int) ([]obfuscatedScript, error) {
	if count <= 0 {
		return []obfuscatedScript{}, nil
	}

	variants := make([]obfuscatedScript, 0, count)

	bundle := c.buildChallengeBundle()

	for range count {
		o := obfuscatedScript{}
		o.uuid = uuid.New()
		obfuscatedJS, err := c.ObfuscateJS(ctx, bundle)
		if err != nil {
			return nil, err
		}
		o.Code = obfuscatedJS
		variants = append(variants, o)
	}

	return variants, nil
}

func (c *ChallengeRuntime) appendLibraryBundle(variants []obfuscatedScript) {
	if len(variants) == 0 {
		return
	}

	c.libraryBundlePoolMu.Lock()
	c.libraryBundlePool = append(c.libraryBundlePool, variants...)
	if len(c.libraryBundlePool) > c.libraryPoolSize {
		c.libraryBundlePool = c.libraryBundlePool[len(c.libraryBundlePool)-c.libraryPoolSize:]
	}
	c.libraryBundlePoolMu.Unlock()
}

// getLibraryBundle picks one variant from the library bundle pool at
// random. When the pool holds a single variant (default state: just the
// baked-in initial bundle), every render returns the same bundle. When
// the pool has grown via the refresher (opt-in), each render selects
// uniformly across the variants for per-visitor byte variance.
func (c *ChallengeRuntime) getLibraryBundle() obfuscatedScript {
	c.libraryBundlePoolMu.RLock()
	defer c.libraryBundlePoolMu.RUnlock()

	poolSize := len(c.libraryBundlePool)
	if poolSize == 0 {
		return obfuscatedScript{}
	}

	idx := rand.IntN(poolSize)
	return c.libraryBundlePool[idx]
}
