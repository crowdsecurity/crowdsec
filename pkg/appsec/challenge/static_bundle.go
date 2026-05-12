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

// initialBundleGz is a pre-obfuscated challenge bundle produced at build time
// by `go generate ./pkg/appsec/challenge/js/...`. It is used to seed the
// challenge JS cache at startup so the service is ready to serve challenges
// immediately, instead of waiting ~1 minute for the first variant to be
// generated synchronously. Background generation continues to add fresh
// variants and rotate them on the normal refresh interval.
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
// (initial_bundle.js.gz) and inserts it into the cache as the first variant.
// Cheap (~ms) — eliminates the ~1 minute synchronous obfuscation that startup
// would otherwise pay.
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

	c.appendCachedChallengeJS([]obfuscatedScript{{
		Code: initialBundle,
		uuid: uuid.New(),
	}})

	return nil
}

// challengeGenerator is the background goroutine that keeps the static-
// bundle cache fresh. It fills the cache to capacity on startup, then
// regenerates the full set on each refresh tick.
func (c *ChallengeRuntime) challengeGenerator(ctx context.Context) {
	// Startup warm-up: grow the cache in background until full.
	if err := c.fillCacheToCapacity(ctx); err != nil {
		log.Errorf("failed to prefill challenge JS cache: %v", err)
	}

	ticker := time.NewTicker(challengeJSRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			variants, err := c.generateChallengeVariants(ctx, challengeJSCacheSize)
			if err != nil {
				log.Errorf("failed to regenerate full challenge JS cache: %v", err)
				continue
			}

			c.replaceCachedChallengeJS(variants)
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

func (c *ChallengeRuntime) generateAndCacheChallengeJS(ctx context.Context) error {
	variants, err := c.generateChallengeVariants(ctx, 1)
	if err != nil {
		return err
	}

	c.appendCachedChallengeJS(variants)

	return nil
}

func (c *ChallengeRuntime) generateChallengeVariants(ctx context.Context, count int) ([]obfuscatedScript, error) {
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

func (c *ChallengeRuntime) fillCacheToCapacity(ctx context.Context) error {
	c.cacheMutex.RLock()
	missing := challengeJSCacheSize - len(c.obfuscatedJSCache)
	c.cacheMutex.RUnlock()

	if missing <= 0 {
		return nil
	}

	variants, err := c.generateChallengeVariants(ctx, missing)
	if err != nil {
		return err
	}

	c.appendCachedChallengeJS(variants)
	return nil
}

func (c *ChallengeRuntime) appendCachedChallengeJS(variants []obfuscatedScript) {
	if len(variants) == 0 {
		return
	}

	c.cacheMutex.Lock()
	c.obfuscatedJSCache = append(c.obfuscatedJSCache, variants...)
	if len(c.obfuscatedJSCache) > challengeJSCacheSize {
		c.obfuscatedJSCache = c.obfuscatedJSCache[len(c.obfuscatedJSCache)-challengeJSCacheSize:]
	}
	c.cacheMutex.Unlock()
}

func (c *ChallengeRuntime) replaceCachedChallengeJS(variants []obfuscatedScript) {
	if len(variants) == 0 {
		return
	}

	c.cacheMutex.Lock()
	c.obfuscatedJSCache = append([]obfuscatedScript(nil), variants...)
	c.cacheMutex.Unlock()
}

func (c *ChallengeRuntime) getCachedChallengeJS() obfuscatedScript {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	cacheSize := len(c.obfuscatedJSCache)
	if cacheSize == 0 {
		return obfuscatedScript{}
	}

	idx := rand.IntN(cacheSize)
	return c.obfuscatedJSCache[idx]
}
