// Package challenge dynamic_module.go handles the **sensitive** per-epoch
// sign-key module — the small JS that embeds the current epoch's HMAC
// key (~30 lines, expanded to ~10-30KB after obfuscation). This is the
// actual cryptographic material protected by the challenge runtime;
// obfuscation here is doing real work, not cosmetic byte variance.
//
// The module is rebuilt whenever the keyring advances to a new epoch
// (default cadence: 5 minutes via keyringDefaultRotation). To give
// per-visitor variance in how the same key is embedded, the runtime
// keeps a small pool of cryptoPoolSize variants per epoch — each
// variant is an independent obfuscation of the same input. Default
// pool size is 1, preserving the historical single-variant-per-epoch
// behaviour; operators that want per-visitor variance for the
// sensitive code can raise WithCryptoObfuscationPoolSize.
//
// For the **non-sensitive** library bundle (public fpscanner / PoW
// worker glue, controlled by WithLibraryRuntimeObfuscationEnabled), see
// static_bundle.go.
package challenge

import (
	"context"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

//go:embed dynamic_module.js.tmpl
var dynamicModuleTemplate string

// preWarmLeadTime returns how far before the next rotation boundary we want
// to start obfuscating the upcoming epoch's dynamic module. Capped at 30s
// (no point starting much earlier — the module is unused until the
// boundary), floored at 1s so very small rotation intervals don't make the
// ticker degenerate into a tight loop.
func (c *ChallengeRuntime) preWarmLeadTime() time.Duration {
	lead := c.keys.rotationInterval / 4
	if lead > 30*time.Second {
		lead = 30 * time.Second
	}
	if lead < time.Second {
		lead = time.Second
	}
	return lead
}

// dynamicModulePreWarmer runs in the background and obfuscates the next
// epoch's dynamic key module (all cryptoPoolSize variants) shortly before
// the rotation boundary, so the first request after a rotation finds the
// module already cached and pays no obfuscation latency on the
// request-serving path.
//
// The ticker goroutine calls dynamicModuleForEpoch synchronously. The
// singleflight inside that call coalesces a real request that arrives
// slightly after the rotation, and time.Ticker drops ticks while the
// receiver is busy — so successive triggers during a single obfuscation
// are naturally absorbed.
func (c *ChallengeRuntime) dynamicModulePreWarmer(ctx context.Context) {
	leadTime := c.preWarmLeadTime()
	tick := time.NewTicker(leadTime)
	defer tick.Stop()

	intervalSecs := int64(c.keys.rotationInterval / time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := c.keys.now()
			current := c.keys.CurrentEpoch()
			nextBoundary := time.Unix((current+1)*intervalSecs, 0)

			// Skip ticks that are not yet inside the lead-time window
			// before the next boundary — pre-warming a far-future epoch
			// would waste CPU on a module that might never be served.
			if nextBoundary.Sub(now) > leadTime {
				continue
			}

			nextEpoch := current + 1
			c.log().WithFields(log.Fields{
				"epoch":               nextEpoch,
				"current_epoch":       current,
				"seconds_to_boundary": int64(nextBoundary.Sub(now).Seconds()),
				"pool_size":           c.cryptoPoolSize,
			}).Debug("pre-warming dynamic key module for upcoming epoch")

			if _, err := c.dynamicModuleForEpoch(ctx, nextEpoch); err != nil {
				c.log().WithError(err).WithField("epoch", nextEpoch).
					Warn("pre-warm of next epoch failed; first request after rotation will pay obfuscation cost")
			}
		}
	}
}

// dynamicModuleForEpoch returns the slice of obfuscated per-epoch key
// module variants for the given epoch, deriving the per-epoch key on
// demand from the keyring and generating cryptoPoolSize obfuscations of
// it. The result is cached; concurrent calls for the same epoch are
// coalesced via singleflight so only one batch obfuscation runs even
// under a thundering-herd arrival pattern at a rotation boundary.
//
// The cache mutex is only held for the fast read/write of the map,
// never across the obfuscation calls — concurrent requests for the same
// epoch coalesce via singleflight rather than serialize on the mutex.
func (c *ChallengeRuntime) dynamicModuleForEpoch(ctx context.Context, epoch int64) ([]string, error) {
	// Fast path: cached.
	c.dynamicModuleCacheMu.RLock()
	if cached, ok := c.dynamicModuleCache[epoch]; ok {
		c.dynamicModuleCacheMu.RUnlock()
		return cached, nil
	}
	c.dynamicModuleCacheMu.RUnlock()

	// Slow path: deduplicate concurrent obfuscation calls for the same
	// epoch. Only one goroutine runs the obfuscator batch; the others
	// block on the singleflight result. The key is the epoch itself,
	// formatted as a string.
	key := strconv.FormatInt(epoch, 10)
	v, err, _ := c.dynamicModuleSF.Do(key, func() (interface{}, error) {
		// Re-check the cache inside the singleflight callback in case
		// another goroutine populated it between the fast-path read and
		// our entry into Do.
		c.dynamicModuleCacheMu.RLock()
		if cached, ok := c.dynamicModuleCache[epoch]; ok {
			c.dynamicModuleCacheMu.RUnlock()
			return cached, nil
		}
		c.dynamicModuleCacheMu.RUnlock()

		signKey, ok := c.keys.SignKey(epoch)
		if !ok {
			return nil, fmt.Errorf("epoch %d is outside the keyring live window", epoch)
		}

		tmpl, err := template.New("dynamic-module").Parse(dynamicModuleTemplate)
		if err != nil {
			return nil, fmt.Errorf("parse dynamic module template: %w", err)
		}
		var rendered strings.Builder
		if err := tmpl.Execute(&rendered, map[string]interface{}{
			"Key":   hex.EncodeToString(signKey),
			"Epoch": epoch,
		}); err != nil {
			return nil, fmt.Errorf("render dynamic module template: %w", err)
		}
		input := rendered.String()
		inputSize := len(input)

		poolSize := c.cryptoPoolSize
		if poolSize < 1 {
			poolSize = 1
		}

		variants := make([]string, 0, poolSize)
		batchStart := time.Now()
		for i := 0; i < poolSize; i++ {
			obfuscateStart := time.Now()
			obfuscated, err := c.ObfuscateJS(ctx, input)
			obfuscateDuration := time.Since(obfuscateStart)
			if err != nil {
				return nil, fmt.Errorf("obfuscate dynamic module variant %d/%d: %w", i+1, poolSize, err)
			}
			if obfuscated == "" {
				return nil, fmt.Errorf("obfuscator produced empty dynamic module output (variant %d/%d)", i+1, poolSize)
			}

			c.log().WithFields(log.Fields{
				"epoch":        epoch,
				"variant":      i,
				"input_bytes":  inputSize,
				"output_bytes": len(obfuscated),
				"duration_ms":  obfuscateDuration.Milliseconds(),
			}).Debug("obfuscated dynamic key module variant")

			variants = append(variants, obfuscated)
		}

		c.log().WithFields(log.Fields{
			"epoch":       epoch,
			"variants":    poolSize,
			"batch_ms":    time.Since(batchStart).Milliseconds(),
			"input_bytes": inputSize,
		}).Debug("obfuscated dynamic key module batch for new epoch")

		c.dynamicModuleCacheMu.Lock()
		// Prune any cached modules whose epoch has fallen out of the
		// live window before inserting the new one.
		live := make(map[int64]bool, len(c.dynamicModuleCache))
		for _, e := range c.keys.LiveEpochs() {
			live[e] = true
		}
		for e := range c.dynamicModuleCache {
			if !live[e] {
				delete(c.dynamicModuleCache, e)
			}
		}
		c.dynamicModuleCache[epoch] = variants
		c.dynamicModuleCacheMu.Unlock()

		return variants, nil
	})
	if err != nil {
		return nil, err
	}

	return v.([]string), nil
}

// currentDynamicModule returns one of the obfuscated dynamic-module
// variants for the keyring's current epoch, selected uniformly at
// random. When the pool size is 1 (default), every render returns the
// same variant; when raised via WithCryptoObfuscationPoolSize, each
// render picks one of the N variants of the same epoch key.
func (c *ChallengeRuntime) currentDynamicModule(ctx context.Context) (string, error) {
	epoch, _ := c.keys.Current()
	variants, err := c.dynamicModuleForEpoch(ctx, epoch)
	if err != nil {
		return "", err
	}
	if len(variants) == 0 {
		return "", fmt.Errorf("dynamic module pool is empty for epoch %d", epoch)
	}
	if len(variants) == 1 {
		return variants[0], nil
	}
	return variants[rand.IntN(len(variants))], nil
}
