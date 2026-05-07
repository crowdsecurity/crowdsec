package challenge

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "embed"

	"text/template"

	challengejs "github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/js"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"golang.org/x/sync/singleflight"
)

const ChallengeJSPath = "/crowdsec-internal/challenge/challenge.js"
const ChallengeSubmitPath = "/crowdsec-internal/challenge/submit"
const ChallengePowWorkerPath = "/crowdsec-internal/challenge/pow-worker.js"
const ChallengeCookieName = "__crowdsec_challenge"
const challengeJSCacheSize = 10
const challengeJSRefreshInterval = 10 * time.Minute

// PoW difficulty levels in leading zero bits. Pure JS SHA-256 through the
// obfuscator runs ~500-5000 ops/sec, so keep these conservative.
const (
	PowDifficultyDisabled   = 0   // no PoW required, nonce "0" always valid
	PowDifficultyLow        = 10  // ~1024 avg iterations ≈ 0.2-2s
	PowDifficultyMedium     = 12  // ~4096 avg iterations ≈ 1-8s
	PowDifficultyHigh       = 15  // ~32768 avg iterations ≈ 7-60s
	PowDifficultyImpossible = 256 // full SHA-256 width: clients cannot solve, server always rejects

	defaultPowDifficulty = PowDifficultyMedium
)

const DefaultChallengeCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; worker-src 'self' blob:;"

//go:embed challenge.html.tmpl
var htmlTemplate string

//go:embed pow-worker.js
var PowWorkerJS string

//go:embed dynamic_module.js.tmpl
var dynamicModuleTemplate string

//go:embed js/obfuscate/index.wasm.gz
var obfuscatorWasmGz []byte

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
	obfuscatorWasm     []byte
	obfuscatorWasmOnce sync.Once
	initialBundle      string
	initialBundleOnce  sync.Once
	initialBundleErr   error
)

type ChallengeRuntime struct {
	r             wazero.Runtime
	obfuscatorMod wazero.CompiledModule

	obfuscatedJSCache []obfuscatedScript
	cacheMutex        sync.RWMutex

	powDifficulty int

	// keys derives per-epoch sign+cookie keys from the configured long-lived
	// secret. All HMAC and AEAD operations route through this so that
	// rotation is a server-side bookkeeping change with no protocol impact.
	// In distributed setups, every WAF instance with the same master_secret
	// and rotation_interval derives bit-identical per-epoch keys.
	keys *KeyRing

	// dynamicModuleCache memoizes the obfuscated per-epoch key module so we
	// only pay the wazero / javascript-obfuscator cost once per epoch. The
	// dynamic module is small (~30 lines), so each obfuscation call costs a
	// few seconds on first call and is then served from memory until the
	// epoch advances. Stale entries are pruned on every Get.
	//
	// dynamicModuleSF de-duplicates concurrent obfuscation requests for the
	// same epoch: if N requests hit a freshly-rotated epoch simultaneously,
	// only one runs the obfuscator and the others wait for its result. The
	// cache mutex is held only for the fast read/write of the map, never
	// across the multi-second obfuscation pass — without this, every
	// rotation boundary serialized incoming traffic and clients dropped
	// the connection before the queue drained.
	dynamicModuleCache   map[int64]string
	dynamicModuleCacheMu sync.RWMutex
	dynamicModuleSF      singleflight.Group

	// nextEpochWarmed records the latest future epoch we've already
	// obfuscated ahead of its boundary so we don't redundantly schedule
	// pre-warm work for the same epoch.
	nextEpochWarmed   int64
	nextEpochWarmedMu sync.Mutex
}

// Option configures a ChallengeRuntime at construction time.
type Option func(*runtimeOptions)

type runtimeOptions struct {
	// masterSecret, if non-nil, overrides the secret-resolution path. The
	// caller is responsible for ensuring it is at least minSecretBytes long.
	masterSecret []byte

	// rotationInterval is the wall-clock period after which the per-epoch
	// derived keys advance. Zero falls back to keyringDefaultRotation.
	rotationInterval time.Duration

	// maxLiveEpochs is how many past epochs (plus the current one) the
	// keyring keeps acceptable. Zero falls back to keyringDefaultMaxLive.
	maxLiveEpochs int
}

// WithMasterSecret sets the long-lived shared secret. In distributed
// deployments this MUST be the same across all WAF instances. If not set,
// NewChallengeRuntime generates a random secret at startup (suitable only for
// single-instance deployments — restarts invalidate outstanding cookies).
func WithMasterSecret(secret []byte) Option {
	return func(o *runtimeOptions) {
		o.masterSecret = secret
	}
}

// WithRotationInterval sets the per-epoch key rotation period. All instances
// in a distributed setup MUST agree on this value to derive identical keys.
func WithRotationInterval(d time.Duration) Option {
	return func(o *runtimeOptions) {
		o.rotationInterval = d
	}
}

// WithMaxLiveEpochs sets how many past epochs (in addition to the current
// one) the keyring continues to accept. Sized so any submission within the
// freshness window has a non-evicted epoch.
func WithMaxLiveEpochs(n int) Option {
	return func(o *runtimeOptions) {
		o.maxLiveEpochs = n
	}
}

// DifficultyFromLevel resolves a named level ("low", "medium", "high") to
// a PoW difficulty in leading zero bits. Case-insensitive.
func DifficultyFromLevel(level string) (int, error) {
	switch strings.ToLower(level) {
	case "disabled":
		return PowDifficultyDisabled, nil
	case "low":
		return PowDifficultyLow, nil
	case "medium":
		return PowDifficultyMedium, nil
	case "high":
		return PowDifficultyHigh, nil
	case "impossible":
		return PowDifficultyImpossible, nil
	default:
		return 0, fmt.Errorf("unknown challenge difficulty %q (expected disabled, low, medium, high, or impossible)", level)
	}
}

// Difficulty returns the current default PoW difficulty (in leading zero bits).
func (c *ChallengeRuntime) Difficulty() int {
	return c.powDifficulty
}

// SetDifficulty sets the default PoW difficulty from a named level.
func (c *ChallengeRuntime) SetDifficulty(level string) error {
	bits, err := DifficultyFromLevel(level)
	if err != nil {
		return err
	}

	c.powDifficulty = bits

	return nil
}

type obfuscatedScript struct {
	Code string    // the obfuscated JS code
	uuid uuid.UUID // unique ID to track the script
}

func NewChallengeRuntime(ctx context.Context, opts ...Option) (*ChallengeRuntime, error) {
	resolvedOpts := runtimeOptions{}
	for _, opt := range opts {
		opt(&resolvedOpts)
	}

	secret := resolvedOpts.masterSecret
	if secret == nil {
		var err error
		secret, err = generateRandomSecret()
		if err != nil {
			return nil, err
		}
		log.Warn("no master secret configured for the WAF challenge runtime; generated an ephemeral random secret. " +
			"Distributed (multi-WAF) deployments MUST configure a shared master_secret in the appsec config; " +
			"single-instance deployments will see outstanding challenge cookies invalidated on restart.")
	} else if len(secret) < minSecretBytes {
		return nil, fmt.Errorf("master secret is %d bytes; minimum is %d", len(secret), minSecretBytes)
	}

	rotationInterval := resolvedOpts.rotationInterval
	if rotationInterval == 0 {
		rotationInterval = keyringDefaultRotation
	}

	keys, err := NewKeyRing(secret, rotationInterval, resolvedOpts.maxLiveEpochs)
	if err != nil {
		return nil, fmt.Errorf("build challenge keyring: %w", err)
	}

	r := wazero.NewRuntime(ctx)

	// No need to keep the closer around, we can just close the runtime itself when stopping
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		return nil, fmt.Errorf("failed to instantiate WASI: %w", err)
	}

	var obfuscatorWasmErr error

	obfuscatorWasmOnce.Do(func() {
		r, err := gzip.NewReader(bytes.NewReader(obfuscatorWasmGz))
		if err != nil {
			obfuscatorWasmErr = fmt.Errorf("failed to create gzip reader for obfuscator wasm: %w", err)
			return
		}
		defer r.Close()

		obfuscatorWasm, err = io.ReadAll(r)
		if err != nil {
			obfuscatorWasmErr = fmt.Errorf("failed to decompress obfuscator wasm: %w", err)
			return
		}
	})

	if obfuscatorWasmErr != nil {
		return nil, obfuscatorWasmErr
	}

	// Pre-compile the obfuscator WASM once. Without this, every ObfuscateJS
	// call re-parses the WASM bytes (~4-5s of overhead per call). Compiling
	// once and instantiating on each call drops per-call overhead to the
	// instantiation cost alone.
	compiledMod, err := r.CompileModule(ctx, obfuscatorWasm)
	if err != nil {
		return nil, fmt.Errorf("failed to compile obfuscator wasm module: %w", err)
	}

	challengeRuntime := &ChallengeRuntime{
		r:                  r,
		obfuscatorMod:      compiledMod,
		obfuscatedJSCache:  make([]obfuscatedScript, 0, challengeJSCacheSize),
		powDifficulty:      defaultPowDifficulty,
		keys:               keys,
		dynamicModuleCache: make(map[int64]string),
	}

	// Seed the cache from the baked-in pre-obfuscated bundle so the service is
	// immediately ready to serve challenges. The background generator below
	// continues to add fresh runtime-generated variants and rotates them on
	// the normal refresh interval.
	if err := challengeRuntime.seedCacheFromInitialBundle(); err != nil {
		// If the initial bundle is missing or corrupt, fall back to the old
		// behavior of generating one variant synchronously. This keeps the
		// service correct even if `go generate` was not run.
		log.Warnf("failed to load baked-in initial challenge bundle (%v); falling back to synchronous generation", err)
		if err := challengeRuntime.generateAndCacheChallengeJS(ctx); err != nil {
			return nil, fmt.Errorf("failed to generate initial challenge bundle: %w", err)
		}
	}

	// Pre-warm the dynamic key module for the current epoch so the very
	// first GetChallengePage call doesn't pay the ~5s obfuscation cost
	// on the request-serving path. The dynamic module is small enough
	// that this stays well under the startup budget.
	if _, err := challengeRuntime.buildAndObfuscateDynamicModule(ctx); err != nil {
		return nil, fmt.Errorf("warm dynamic key module: %w", err)
	}

	go challengeRuntime.challengeGenerator(ctx)
	go challengeRuntime.dynamicModulePreWarmer(ctx)

	return challengeRuntime, nil
}

// dynamicModulePreWarmer runs in the background and obfuscates the next
// epoch's dynamic key module shortly before the rotation boundary, so the
// first request after a rotation finds the module already cached and pays
// no obfuscation latency on the request-serving path.
//
// Without this, every rotation boundary stalled concurrent incoming
// requests behind a multi-second obfuscation pass — clients dropped the
// connection and the WAF logged "broken pipe" errors.
func (c *ChallengeRuntime) dynamicModulePreWarmer(ctx context.Context) {
	// Pre-warm at most a quarter of a rotation interval before the
	// boundary, capped at 30s. Sub-second floor so very small intervals
	// don't degenerate into a tight loop.
	leadTime := c.keys.rotationInterval / 4
	if leadTime > 30*time.Second {
		leadTime = 30 * time.Second
	}
	if leadTime < time.Second {
		leadTime = time.Second
	}

	tick := time.NewTicker(leadTime)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.maybePreWarmNextEpoch(ctx)
		}
	}
}

// maybePreWarmNextEpoch checks whether we are inside the lead-time window
// before the next rotation; if so, and we haven't already pre-warmed that
// epoch, obfuscate it now in the background.
func (c *ChallengeRuntime) maybePreWarmNextEpoch(ctx context.Context) {
	now := c.keys.now()
	current := c.keys.CurrentEpoch()
	intervalSecs := int64(c.keys.rotationInterval / time.Second)
	nextBoundary := time.Unix((current+1)*intervalSecs, 0)
	leadTime := c.keys.rotationInterval / 4
	if leadTime > 30*time.Second {
		leadTime = 30 * time.Second
	}

	// Only pre-warm if we are within the lead-time window before the
	// next boundary. This avoids generating a far-future module that
	// might never be served (cheaper rotation cadence is forgiving;
	// long cadence with eager pre-warm wastes CPU on every tick).
	if nextBoundary.Sub(now) > leadTime {
		return
	}

	nextEpoch := current + 1

	c.nextEpochWarmedMu.Lock()
	if c.nextEpochWarmed >= nextEpoch {
		c.nextEpochWarmedMu.Unlock()
		return
	}
	c.nextEpochWarmed = nextEpoch
	c.nextEpochWarmedMu.Unlock()

	// Run the pre-warm asynchronously so the ticker goroutine isn't
	// blocked for the full obfuscation duration. dynamicModuleForEpoch
	// is single-flight protected so this can race safely with a
	// real request that arrives slightly after the rotation.
	go func() {
		log.WithFields(log.Fields{
			"epoch":           nextEpoch,
			"current_epoch":   current,
			"seconds_to_boundary": int64(nextBoundary.Sub(now).Seconds()),
		}).Info("WAF challenge: pre-warming dynamic key module for upcoming epoch")

		if _, err := c.dynamicModuleForEpoch(ctx, nextEpoch); err != nil {
			log.WithError(err).WithField("epoch", nextEpoch).
				Warn("WAF challenge: pre-warm of next epoch failed; first request after rotation will pay obfuscation cost")
		}
	}()
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

func (c *ChallengeRuntime) ObfuscateJS(ctx context.Context, inputJS string) (string, error) {
	stdin := bytes.NewReader([]byte(inputJS))
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	config := wazero.NewModuleConfig().
		WithStdin(stdin).
		WithStdout(&stdout).
		WithStderr(&stderr)

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

// computeTicket signs the timestamp with the per-epoch signing key derived
// from the master secret. The epoch is computed from the timestamp itself
// (`ts_nanos / 1e9 / rotation_seconds`), so verification is fully stateless:
// any instance with the same master secret can derive the same epoch from the
// same ts and validate the HMAC.
// dynamicModuleForEpoch returns the obfuscated per-epoch key module for the
// given epoch, deriving the per-epoch key on demand from the keyring. The
// result is cached; concurrent calls for the same epoch are coalesced via
// singleflight so only one obfuscation runs even under a thundering-herd
// arrival pattern at a rotation boundary.
//
// IMPORTANT: the cache mutex is never held across the (multi-second)
// obfuscation. Earlier versions held it for the entire build, which
// serialized every concurrent request behind a 5-second-wide window every
// rotation and caused upstream connections to drop with broken-pipe errors.
func (c *ChallengeRuntime) dynamicModuleForEpoch(ctx context.Context, epoch int64) (string, error) {
	// Fast path: cached.
	c.dynamicModuleCacheMu.RLock()
	if cached, ok := c.dynamicModuleCache[epoch]; ok {
		c.dynamicModuleCacheMu.RUnlock()
		return cached, nil
	}
	c.dynamicModuleCacheMu.RUnlock()

	// Slow path: deduplicate concurrent obfuscation calls for the same
	// epoch. Only one goroutine runs the obfuscator; the others block on
	// the singleflight result. The key is the epoch itself, formatted as
	// a string.
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
			return "", fmt.Errorf("epoch %d is outside the keyring live window", epoch)
		}

		obfuscated, err := c.obfuscateDynamicModuleForEpoch(ctx, epoch, signKey)
		if err != nil {
			return "", err
		}

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
		c.dynamicModuleCache[epoch] = obfuscated
		c.dynamicModuleCacheMu.Unlock()

		return obfuscated, nil
	})
	if err != nil {
		return "", err
	}

	return v.(string), nil
}

// buildAndObfuscateDynamicModule produces (or returns from cache) the
// dynamic key module for the keyring's *current* epoch. Wrapper around
// dynamicModuleForEpoch for the request-serving path.
func (c *ChallengeRuntime) buildAndObfuscateDynamicModule(ctx context.Context) (string, error) {
	epoch, _ := c.keys.Current()
	return c.dynamicModuleForEpoch(ctx, epoch)
}

// obfuscateDynamicModuleForEpoch is the actual obfuscation work: render the
// template with the per-epoch key, run it through the obfuscator wasm,
// emit the perf log line. Caller is responsible for caching.
func (c *ChallengeRuntime) obfuscateDynamicModuleForEpoch(ctx context.Context, epoch int64, signKey []byte) (string, error) {
	tmpl, err := template.New("dynamic-module").Parse(dynamicModuleTemplate)
	if err != nil {
		return "", fmt.Errorf("parse dynamic module template: %w", err)
	}
	var rendered strings.Builder
	if err := tmpl.Execute(&rendered, map[string]interface{}{
		"Key":   hex.EncodeToString(signKey),
		"Epoch": epoch,
	}); err != nil {
		return "", fmt.Errorf("render dynamic module template: %w", err)
	}
	inputSize := rendered.Len()

	obfuscateStart := time.Now()
	obfuscated, err := c.ObfuscateJS(ctx, rendered.String())
	obfuscateDuration := time.Since(obfuscateStart)
	if err != nil {
		return "", fmt.Errorf("obfuscate dynamic module: %w", err)
	}
	if obfuscated == "" {
		return "", fmt.Errorf("obfuscator produced empty dynamic module output")
	}

	log.WithFields(log.Fields{
		"epoch":        epoch,
		"input_bytes":  inputSize,
		"output_bytes": len(obfuscated),
		"duration_ms":  obfuscateDuration.Milliseconds(),
	}).Info("WAF challenge: obfuscated dynamic key module for new epoch")

	return obfuscated, nil
}

func (c *ChallengeRuntime) computeTicket(ts string) string {
	epoch := c.epochForTimestamp(ts)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		// Falling back to the current key on out-of-window timestamps avoids
		// accidentally producing a structurally valid signature for a stale
		// timestamp; verification will reject the resulting ticket on the same
		// liveness check.
		_, signKey = c.keys.Current()
	}

	h := hmac.New(sha256.New, signKey)
	h.Write([]byte(ts))

	return fmt.Sprintf("%x", h.Sum(nil))
}

// epochForTimestamp converts a nanosecond UnixNano string (the format used in
// challenge.go's ts) into the keyring's epoch identifier. Uses the same
// rotation interval as the keyring so two instances always agree.
func (c *ChallengeRuntime) epochForTimestamp(ts string) int64 {
	tsVal, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || tsVal <= 0 {
		// Caller will reject the ticket via the liveness check anyway; return
		// an out-of-window sentinel epoch.
		return -1
	}
	return tsVal / int64(time.Second) / int64(c.keys.rotationInterval/time.Second)
}

// GetChallengePage renders the challenge HTML page with the given PoW difficulty.
// If difficulty is 0, the default difficulty is used.
func (c *ChallengeRuntime) GetChallengePage(userAgent string, difficulty int) (string, error) {
	_ = userAgent

	if difficulty <= 0 {
		difficulty = c.powDifficulty
	}

	// We are using text/template instead of html/template because the data we send is pretty much hardcoded and trusted.
	// Using html/template would escape the JS code we are adding, making it unusable.
	templateObj, err := template.New("challenge").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse challenge template: %w", err)
	}

	obfuscatedJS := c.getCachedChallengeJS()
	if obfuscatedJS.Code == "" {
		if err := c.generateAndCacheChallengeJS(context.Background()); err != nil {
			return "", fmt.Errorf("failed to generate challenge JS: %w", err)
		}
		obfuscatedJS = c.getCachedChallengeJS()
		if obfuscatedJS.Code == "" {
			return "", fmt.Errorf("challenge JS cache is empty")
		}
	}

	// All per-request values: timestamp, PoW salt, PoW MAC.
	// Fully stateless — no server-side storage, works across HA instances.
	//
	// The ticket is NO LONGER server-issued; the client computes it itself
	// from the per-epoch key embedded in the dynamic key module (see
	// dynamicModule below). This keeps the signing material inside the
	// obfuscated payload — an attacker scraping HTML can no longer recover
	// it for browser impersonation.
	//
	// The ticket the server expects is HMAC(ts, K_epoch). To satisfy
	// computePowMAC's contract (it binds the salt to a specific ticket+ts)
	// we still compute the same ticket here.
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	ticket := c.computeTicket(ts)
	powSalt := generatePowPrefix()
	powMAC := c.computePowMAC(powSalt, ticket, ts)

	// Build and (cheaply) obfuscate the dynamic key module for the current
	// epoch. The static bundle in obfuscatedJS.Code only carries the hook
	// registration; the dynamic module is what carries the per-epoch K — so
	// K never appears in plain HTML.
	dynamicModule, err := c.buildAndObfuscateDynamicModule(context.Background())
	if err != nil {
		return "", fmt.Errorf("build dynamic key module: %w", err)
	}

	var renderedPage strings.Builder

	templateObj.Execute(&renderedPage, map[string]interface{}{
		"JSChallenge":   obfuscatedJS.Code,
		"DynamicModule": dynamicModule,
		"PowDifficulty": difficulty,
		"PowPrefix":     powSalt,
		"PowMAC":        powMAC,
		"Timestamp":     ts,
	})
	return renderedPage.String(), nil
}

func generatePowPrefix() string {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate PoW prefix: %v", err))
	}

	return hex.EncodeToString(buf)
}

// computePowMAC produces an HMAC that authenticates a PoW salt as server-
// generated and bound to a specific ticket window. Signed with the same
// per-epoch key as the ticket so a single keyring lookup verifies both.
func (c *ChallengeRuntime) computePowMAC(salt, ticket, ts string) string {
	epoch := c.epochForTimestamp(ts)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		_, signKey = c.keys.Current()
	}

	h := hmac.New(sha256.New, signKey)
	h.Write([]byte(salt))
	h.Write([]byte(ticket))
	h.Write([]byte(ts))

	return fmt.Sprintf("%x", h.Sum(nil))
}

func hasLeadingZeroBits(hash []byte, bits int) bool {
	fullBytes := bits / 8
	remainBits := bits % 8

	for i := range fullBytes {
		if hash[i] != 0 {
			return false
		}
	}

	if remainBits > 0 {
		mask := byte(0xFF << (8 - remainBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

func (c *ChallengeRuntime) getSessionKey(ticket string, nonce string) string {
	hash := sha256.Sum256([]byte(ticket + nonce))
	return fmt.Sprintf("%x", hash)
}

func (c *ChallengeRuntime) decryptFingerprint(sessionKey string, encrypted string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted fingerprint: %w", err)
	}

	decryptedBytes := make([]byte, len(encryptedBytes))

	for i := range encryptedBytes {
		decryptedBytes[i] = encryptedBytes[i] ^ sessionKey[i%len(sessionKey)]
	}

	return string(decryptedBytes), nil
}

// matchesChallenge verifies that the ticket/timestamp/PoW salt are authentically
// server-generated and the timestamp is recent. Fully stateless — any instance
// sharing the master secret can verify.
//
// Both the ticket and the PoW MAC are signed with the per-epoch key derived
// from `ts`. Liveness is enforced twice: first via the keyring (the epoch
// derived from `ts` must be in the live window) and second via the
// challenge-JS refresh window. The keyring window is the actual freshness
// guarantee; the JS-refresh check is a (looser) backstop.
func (c *ChallengeRuntime) matchesChallenge(clientTicket, clientTS, clientPowSalt, clientPowMAC string) bool {
	tsVal, err := strconv.ParseInt(clientTS, 10, 64)
	if err != nil || tsVal <= 0 {
		return false
	}

	age := time.Since(time.Unix(0, tsVal))
	if age < 0 || age > 2*challengeJSRefreshInterval {
		return false
	}

	epoch := c.epochForTimestamp(clientTS)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		// Epoch fell out of the live window — reject without leaking a usable
		// "signature mismatch" vs "stale epoch" distinction via timing.
		return false
	}

	// Verify the ticket is an authentic HMAC of the timestamp under K_epoch.
	expectedTicket := hmacSHA256Hex(signKey, []byte(clientTS))
	if !hmac.Equal([]byte(clientTicket), []byte(expectedTicket)) {
		return false
	}

	// Verify the PoW salt MAC is authentic and bound to this ticket+timestamp.
	macIn := make([]byte, 0, len(clientPowSalt)+len(clientTicket)+len(clientTS))
	macIn = append(macIn, clientPowSalt...)
	macIn = append(macIn, clientTicket...)
	macIn = append(macIn, clientTS...)
	expectedMAC := hmacSHA256Hex(signKey, macIn)

	return hmac.Equal([]byte(clientPowMAC), []byte(expectedMAC))
}

func hmacSHA256Hex(key, msg []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c *ChallengeRuntime) ValidateChallengeResponse(request *http.Request, body []byte) (*cookie.AppsecCookie, FingerprintData, error) {
	vars, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to parse challenge response: %w", err)
	}

	encryptedFingerprint := vars.Get("f")
	clientTicket := vars.Get("t")
	clientTS := vars.Get("ts")
	clientHMAC := vars.Get("h")
	clientNonce := vars.Get("n")
	clientPowSalt := vars.Get("p")
	clientPowMAC := vars.Get("m")

	if encryptedFingerprint == "" || clientTicket == "" || clientTS == "" || clientHMAC == "" || clientNonce == "" || clientPowSalt == "" || clientPowMAC == "" {
		return nil, FingerprintData{}, fmt.Errorf("missing required fields in challenge response")
	}

	// Verify ticket/timestamp match and PoW salt is authentically server-generated (stateless).
	if !c.matchesChallenge(clientTicket, clientTS, clientPowSalt, clientPowMAC) {
		return nil, FingerprintData{}, fmt.Errorf("invalid ticket in challenge response")
	}

	// An impossible difficulty is a deliberate hard-block: clients cannot solve
	// it, and the server must not accept any submission.
	if c.powDifficulty >= PowDifficultyImpossible {
		return nil, FingerprintData{}, fmt.Errorf("challenge difficulty is impossible; submission rejected")
	}

	// Verify proof-of-work: SHA256(powSalt + nonce) must have required leading zero bits
	powHash := sha256.Sum256([]byte(clientPowSalt + clientNonce))
	if !hasLeadingZeroBits(powHash[:], c.powDifficulty) {
		return nil, FingerprintData{}, fmt.Errorf("invalid proof-of-work in challenge response")
	}

	// Derive session key from ticket + nonce (same as client-side)
	sessionKey := c.getSessionKey(clientTicket, clientNonce)

	// Verify HMAC over encrypted fingerprint + timestamp + ticket + nonce
	expectedHMAC := hmac.New(sha256.New, []byte(sessionKey))
	expectedHMAC.Write([]byte(encryptedFingerprint))
	expectedHMAC.Write([]byte(clientTS))
	expectedHMAC.Write([]byte(clientTicket))
	expectedHMAC.Write([]byte(clientNonce))

	expectedHMACHex := fmt.Sprintf("%x", expectedHMAC.Sum(nil))

	if !hmac.Equal([]byte(clientHMAC), []byte(expectedHMACHex)) {
		return nil, FingerprintData{}, fmt.Errorf("invalid HMAC in challenge response")
	}

	fingerprint, err := c.decryptFingerprint(sessionKey, encryptedFingerprint)
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to decrypt fingerprint: %w", err)
	}

	var fpData FingerprintData

	if err := json.Unmarshal([]byte(fingerprint), &fpData); err != nil {
		log.Errorf("fp: %s", fingerprint)
		return nil, FingerprintData{}, fmt.Errorf("failed to unmarshal fingerprint data: %w", err)
	}

	envelope := &pb.ChallengeCookie{
		Fingerprint:   fpData.ToProto(),
		PowDifficulty: int32(c.powDifficulty),
	}

	// Seal under the current epoch's cookie key. The cookie wire format
	// includes the epoch tag so the same key (or a subsequent rotation
	// while the epoch is still in the live window) opens it.
	cookieEpoch, cookieKey := c.keys.CurrentCookie()
	cookieValue, err := sealCookieV1(envelope, cookieKey, cookieEpoch, []byte(request.UserAgent()))
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to seal challenge cookie: %w", err)
	}

	ck := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite(cookie.SameSiteLax).ExpiresIn(2 * time.Hour).Value(cookieValue)
	if request.URL.Scheme == "https" {
		ck = ck.Secure()
	}

	return ck, fpData, nil
}

// CookieData bundles the decrypted fingerprint with cookie-envelope metadata
// (currently just the proven PoW difficulty) so callers can make re-challenge
// decisions without touching the fingerprint struct.
type CookieData struct {
	Fingerprint   FingerprintData
	PowDifficulty int
}

func (c *ChallengeRuntime) ValidCookie(ck *http.Cookie, userAgent string) (*CookieData, error) {
	if ck == nil {
		return nil, fmt.Errorf("nil cookie")
	}

	envelope, err := openCookieV1(ck.Value, c.keys.CookieKey, c.keys.LiveEpochs(), []byte(userAgent))
	if err != nil {
		return nil, fmt.Errorf("invalid challenge cookie: %w", err)
	}

	return &CookieData{
		Fingerprint:   fingerprintDataFromProto(envelope.GetFingerprint()),
		PowDifficulty: int(envelope.GetPowDifficulty()),
	}, nil
}
