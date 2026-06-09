// Package challenge implements the AppSec WAF challenge mode: a PoW-gated
// landing page, a fingerprint collection bundle, and the surrounding key
// rotation + cookie machinery. This file holds the runtime orchestration
// (lifecycle, HTTP entry points, template rendering, hook plumbing) and
// delegates specialized concerns to sibling files in the same package:
//
//   - keyring.go / crypto.go / ticket.go — per-epoch HKDF keys, AES-GCM
//     cookie seal/unseal, ticket signing
//   - static_bundle.go                   — public fpscanner/JS bundle
//   - dynamic_module.go                  — sensitive per-epoch sign-key module
//   - obfuscator.go                      — wazero wrapper around the JS obfuscator
//   - fingerprint*.go                    — fingerprint wire shape + helpers + mismatch report
//   - config.go / secret.go              — YAML config + master-secret handling
package challenge

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
	log "github.com/sirupsen/logrus"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"golang.org/x/sync/singleflight"
)

// Internal URL paths the challenge runtime intercepts. Bouncers MUST forward
// these to the WAF unmodified; they are served by the appsec dispatcher
// (pkg/appsec/appsec.go) rather than by the protected origin.
const (
	ChallengeJSPath        = "/crowdsec-internal/challenge/challenge.js"
	ChallengeSubmitPath    = "/crowdsec-internal/challenge/submit"
	ChallengePowWorkerPath = "/crowdsec-internal/challenge/pow-worker.js"
)

// ChallengeCookieName is the name of the sealed cookie carrying the
// successfully-validated fingerprint between requests.
const ChallengeCookieName = "__crowdsec_challenge"

// libraryBundlePoolDefaultSize caps the library bundle pool. With runtime
// obfuscation off (default) only the baked-in initial_bundle.js.gz variant
// exists (so 1); with it on, this is the ceiling the refresher fills.
const libraryBundlePoolDefaultSize = 1

// libraryBundleRefreshDefaultInterval is how often one new library-bundle
// variant is obfuscated (oldest evicted) when runtime obfuscation is on — one
// per tick, so full rotation takes pool_size × interval.
const libraryBundleRefreshDefaultInterval = time.Hour

// cryptoObfuscationPoolDefaultSize is how many obfuscations of the per-epoch
// key module to keep per live epoch. Each variant embeds the same key
// differently (per-visitor byte variance); default 1 keeps prior behaviour.
const cryptoObfuscationPoolDefaultSize = 1

// defaultCookieTTL is the default challenge-cookie validity. Decoupled from the
// keyring window (enforced by not_after in the envelope), so cookies can
// outlive the per-epoch signing window without widening forgery exposure.
const defaultCookieTTL = 12 * time.Hour

// DefaultChallengeCSP is the Content-Security-Policy header used on the
// challenge page when the operator hasn't configured a custom one. Allows
// inline script/style (the challenge runtime injects both) and blob workers
// (the PoW worker is loaded from a blob URL).
const DefaultChallengeCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; worker-src 'self' blob:;"

//go:embed challenge.html.tmpl
var htmlTemplate string

// grantRedirectBody is the body of the 307 from GrantChallengeCookie — a no-JS
// fallback for HTTP clients that don't auto-follow Location. Static, so no
// per-request parsing is needed.
//
//go:embed grant_redirect.html.tmpl
var GrantRedirectBody string

// PowWorkerJS is the JavaScript PoW worker shipped to the browser at
// ChallengePowWorkerPath. Served as-is — obfuscation here would only slow
// down the per-visitor PoW loop without adding security value.
//
//go:embed pow-worker.js
var PowWorkerJS string

// ChallengeRuntime is the per-process state for the challenge mode: wazero
// instance, signing/cookie keys, obfuscation pools, fingerprint key
// rotation. One instance is shared across all appsec runners (see
// pkg/acquisition/modules/appsec/config.go). Construct via NewChallengeRuntime.
type ChallengeRuntime struct {
	r             wazero.Runtime
	obfuscatorMod wazero.CompiledModule

	// libraryRuntimeObfuscationEnabled gates the library-bundle refresher. The
	// bundle is ALWAYS obfuscated at build time; when false (default) only the
	// baked-in variant is served and no refresher runs. When true, the
	// refresher adds one runtime variant per tick.
	libraryRuntimeObfuscationEnabled bool
	libraryPoolSize                  int
	libraryRefreshInterval           time.Duration

	// libraryBundlePool holds up to libraryPoolSize obfuscated variants of the
	// static bundle, seeded at startup from initial_bundle.js.gz. With
	// obfuscation enabled the refresher appends/trims; the serving path picks
	// one at random per render.
	libraryBundlePool   []obfuscatedScript
	libraryBundlePoolMu sync.RWMutex

	powDifficulty int

	// keys derives per-epoch sign keys (per-challenge secret / PoW MAC HMACs)
	// and the long-lived master cookie key from the master secret. Routing all
	// HMAC/AEAD through it makes rotation a bookkeeping change; instances
	// sharing the secret + rotation interval derive identical keys.
	keys *KeyRing

	// cryptoPoolSize is how many obfuscations of the per-epoch key module to
	// keep per live epoch (per-visitor byte variance over the same key);
	// default 1.
	cryptoPoolSize int

	// dynamicModuleCache memoizes the obfuscated per-epoch key module variants
	// (epoch → cryptoPoolSize renderings); currentDynamicModule picks one at
	// random. dynamicModuleSF coalesces concurrent obfuscations for the same
	// epoch so a rotation thundering-herd pays at most one obfuscation latency
	// per slot, not N. The mutex guards only the map, never the obfuscation.
	dynamicModuleCache   map[int64][]string
	dynamicModuleCacheMu sync.RWMutex
	dynamicModuleSF      singleflight.Group

	// cookieTTL is how long a challenge cookie stays valid. Enforced by the
	// not_after stamp in the sealed envelope (crypto.go), not keyring eviction,
	// so it can exceed the per-epoch signing window.
	cookieTTL time.Duration

	// htmlTpl is the challenge HTML template, parsed once and reused so
	// GetChallengePage doesn't re-parse per request.
	htmlTpl *template.Template

	// spent burns consumed per-challenge nonces (`r`) to enforce single-use and
	// eliminate replay (in-memory, single instance — see spent_set.go).
	spent *spentSet

	// logger is the component logger; its level is set at construction
	// (WithLogger / BuildOptions). All challenge logging routes through it so
	// `log_level` controls verbosity independently of the global logger.
	logger *log.Entry
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

	// cookieTTL controls how long an issued challenge cookie remains
	// valid. Zero falls back to defaultCookieTTL.
	cookieTTL time.Duration

	// cryptoObfuscationPoolSize is the number of distinct obfuscations of
	// the per-epoch sign-key module to keep per live epoch. Zero falls
	// back to cryptoObfuscationPoolDefaultSize.
	cryptoObfuscationPoolSize int

	// libraryRuntimeObfuscationEnabled gates the background re-obfuscation
	// of the static library bundle at runtime. The library bundle is
	// ALWAYS obfuscated at build time; this flag only adds further runtime
	// variants. False (the default) means: serve only the baked-in initial
	// bundle, no refresher goroutine.
	libraryRuntimeObfuscationEnabled bool

	// libraryObfuscationPoolSize is the max number of obfuscated variants
	// of the library bundle to keep. Zero falls back to
	// libraryBundlePoolDefaultSize. Values > 1 only have effect when
	// runtime obfuscation is enabled; otherwise no source produces
	// additional variants and the runtime warns + clamps to 1.
	libraryObfuscationPoolSize int

	// libraryObfuscationRefreshInterval is the cadence at which a single
	// new library-bundle variant is obfuscated and added to the pool when
	// runtime obfuscation is enabled. Zero falls back to
	// libraryBundleRefreshDefaultInterval. Ignored when
	// libraryRuntimeObfuscationEnabled is false.
	libraryObfuscationRefreshInterval time.Duration

	// spentSetMaxEntries caps the replay-protection LRU. Zero falls back to
	// spentSetDefaultMaxEntries.
	spentSetMaxEntries int

	// logger is the component logger (already at the desired level). Nil falls
	// back to a default "challenge" sublogger in NewChallengeRuntime.
	logger *log.Entry
}

func WithLogger(logger *log.Entry) Option {
	return func(o *runtimeOptions) {
		o.logger = logger
	}
}

// log returns the component logger, defaulting to a standard "challenge"
// sublogger when unset (runtimes built directly in tests don't set it).
func (c *ChallengeRuntime) log() *log.Entry {
	if c.logger != nil {
		return c.logger
	}
	return logging.SubLogger(log.StandardLogger(), "challenge", 0)
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

// WithCookieTTL sets challenge-cookie validity. Decoupled from the keyring
// window so cookies can be long-lived (e.g. 24h) while per-epoch keys rotate
// tightly. Zero/negative is ignored (defaultCookieTTL used).
func WithCookieTTL(ttl time.Duration) Option {
	return func(o *runtimeOptions) {
		if ttl > 0 {
			o.cookieTTL = ttl
		}
	}
}

// WithCryptoObfuscationPoolSize sets how many obfuscations of the per-epoch key
// module to keep per live epoch (per-visitor byte variance over the same key).
// Default 1; values below 1 are ignored.
func WithCryptoObfuscationPoolSize(n int) Option {
	return func(o *runtimeOptions) {
		if n >= 1 {
			o.cryptoObfuscationPoolSize = n
		}
	}
}

// WithLibraryRuntimeObfuscationEnabled toggles runtime re-obfuscation of the
// static library bundle. The bundle is always obfuscated at build time; this
// only adds runtime variants. Off by default (serve only the baked-in bundle,
// no obfuscator cost on the static path).
func WithLibraryRuntimeObfuscationEnabled(enabled bool) Option {
	return func(o *runtimeOptions) {
		o.libraryRuntimeObfuscationEnabled = enabled
	}
}

// WithLibraryObfuscationPoolSize sets the max number of runtime-
// obfuscated variants of the library bundle to keep when library
// obfuscation is enabled. Ignored when disabled. Values below 1 are
// ignored; zero falls back to libraryBundlePoolDefaultSize.
func WithLibraryObfuscationPoolSize(n int) Option {
	return func(o *runtimeOptions) {
		if n >= 1 {
			o.libraryObfuscationPoolSize = n
		}
	}
}

// WithLibraryObfuscationRefreshInterval sets the cadence at which a
// single new library-bundle variant is obfuscated and added to the pool
// when library obfuscation is enabled. One obfuscation per tick
// regardless of pool size — full pool rotation takes pool_size ×
// refresh_interval. Ignored when disabled. Values ≤ 0 are ignored.
func WithLibraryObfuscationRefreshInterval(d time.Duration) Option {
	return func(o *runtimeOptions) {
		if d > 0 {
			o.libraryObfuscationRefreshInterval = d
		}
	}
}

// WithSpentSetMaxEntries caps the replay-protection LRU. Sized as a deep DoS
// backstop; steady-state stays far below it. Values below 1 are ignored (the
// default is used).
func WithSpentSetMaxEntries(n int) Option {
	return func(o *runtimeOptions) {
		if n >= 1 {
			o.spentSetMaxEntries = n
		}
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

// NewChallengeRuntime builds and starts a ChallengeRuntime. It initializes
// the wazero runtime, decompresses the baked-in library bundle, derives the
// master secret + keyring, pre-warms the dynamic-module cache, and (if
// configured) spawns the background obfuscation refresher. The returned
// instance is safe for concurrent use across all appsec runners.
//
// Pass functional options (WithMasterSecret, WithKeyringRotationInterval,
// WithLibraryRuntimeObfuscationEnabled, ...) to override defaults; see the
// options in this file for individual semantics.
func NewChallengeRuntime(ctx context.Context, opts ...Option) (*ChallengeRuntime, error) {
	resolvedOpts := runtimeOptions{}
	for _, opt := range opts {
		opt(&resolvedOpts)
	}

	logger := resolvedOpts.logger
	if logger == nil {
		logger = logging.SubLogger(log.StandardLogger(), "challenge", 0)
	}

	secret := resolvedOpts.masterSecret
	if secret == nil {
		var err error
		secret, err = generateRandomSecret()
		if err != nil {
			return nil, err
		}
		logger.Warn("no master secret configured for the WAF challenge runtime; generated an ephemeral random secret. " +
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
	keys.logger = logger

	cookieTTL := resolvedOpts.cookieTTL
	if cookieTTL <= 0 {
		cookieTTL = defaultCookieTTL
	}

	cryptoPoolSize := resolvedOpts.cryptoObfuscationPoolSize
	if cryptoPoolSize <= 0 {
		cryptoPoolSize = cryptoObfuscationPoolDefaultSize
	}

	libraryPoolSize := resolvedOpts.libraryObfuscationPoolSize
	if libraryPoolSize <= 0 {
		libraryPoolSize = libraryBundlePoolDefaultSize
	}

	// Clamp pool size to 1 when runtime obfuscation is off: the only source
	// of variants in that mode is the baked-in initial bundle (one entry),
	// so any larger ceiling would leave empty slots forever. Warn so the
	// operator notices the misconfiguration without having the runtime fail
	// to start.
	if !resolvedOpts.libraryRuntimeObfuscationEnabled && libraryPoolSize > 1 {
		logger.Warnf("library_obfuscation_pool_size=%d ignored: library_runtime_obfuscation_enabled is false, only the baked-in variant will populate the pool. Clamping to 1.", libraryPoolSize)
		libraryPoolSize = 1
	}

	libraryRefreshInterval := resolvedOpts.libraryObfuscationRefreshInterval
	if libraryRefreshInterval <= 0 {
		libraryRefreshInterval = libraryBundleRefreshDefaultInterval
	}

	spentSetMaxEntries := resolvedOpts.spentSetMaxEntries
	if spentSetMaxEntries <= 0 {
		spentSetMaxEntries = spentSetDefaultMaxEntries
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

	// We use text/template instead of html/template because the data we send
	// is pretty much hardcoded and trusted; html/template would escape the JS
	// we inject. Parsed once here so GetChallengePage doesn't re-parse on
	// every request.
	htmlTpl, err := template.New("challenge").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse challenge html template: %w", err)
	}

	challengeRuntime := &ChallengeRuntime{
		r:                                r,
		obfuscatorMod:                    compiledMod,
		libraryRuntimeObfuscationEnabled: resolvedOpts.libraryRuntimeObfuscationEnabled,
		libraryPoolSize:                  libraryPoolSize,
		libraryRefreshInterval:           libraryRefreshInterval,
		libraryBundlePool:                make([]obfuscatedScript, 0, libraryPoolSize),
		powDifficulty:                    defaultPowDifficulty,
		keys:                             keys,
		cryptoPoolSize:                   cryptoPoolSize,
		dynamicModuleCache:               make(map[int64][]string),
		cookieTTL:                        cookieTTL,
		htmlTpl:                          htmlTpl,
		spent:                            newSpentSet(spentSetMaxEntries),
		logger:                           logger,
	}

	// Seed from the baked-in pre-obfuscated bundle so we can serve immediately.
	if err := challengeRuntime.seedCacheFromInitialBundle(); err != nil {
		// Initial bundle missing/corrupt (e.g. `go generate` not run): fall back
		// to generating one variant synchronously.
		logger.Warnf("failed to load baked-in initial challenge bundle (%v); falling back to synchronous generation", err)
		if err := challengeRuntime.generateAndCacheChallengeJS(ctx); err != nil {
			return nil, fmt.Errorf("failed to generate initial challenge bundle: %w", err)
		}
	}

	// Pre-warm the current epoch's dynamic module so the first GetChallengePage
	// doesn't pay the ~5s obfuscation cost on the request path.
	if _, err := challengeRuntime.currentDynamicModule(ctx); err != nil {
		return nil, fmt.Errorf("warm dynamic key module: %w", err)
	}

	// Library refresher is opt-in: the bundle is public code already served
	// obfuscated, so runtime variants only add byte variance and aren't worth
	// the ~minute-per-pass cost by default.
	if resolvedOpts.libraryRuntimeObfuscationEnabled {
		go challengeRuntime.libraryBundlePoolRefresher(ctx)
	}
	// The dynamic-module pre-warmer is always on — the per-epoch key must be
	// re-obfuscated on every rotation (bounded cost, one pass per variant).
	go challengeRuntime.dynamicModulePreWarmer(ctx)

	logger.WithFields(log.Fields{
		"rotation_interval":   rotationInterval,
		"cookie_ttl":          cookieTTL,
		"pow_difficulty":      defaultPowDifficulty,
		"crypto_pool_size":    cryptoPoolSize,
		"library_pool_size":   libraryPoolSize,
		"library_runtime_obf": resolvedOpts.libraryRuntimeObfuscationEnabled,
	}).Info("WAF challenge runtime initialized")

	return challengeRuntime, nil
}

// GetChallengePage renders the challenge HTML page with the given PoW difficulty.
// If difficulty is 0, the default difficulty is used.
func (c *ChallengeRuntime) GetChallengePage(userAgent string, difficulty int) (string, error) {
	_ = userAgent

	if difficulty <= 0 {
		difficulty = c.powDifficulty
	}

	obfuscatedJS := c.getLibraryBundle()
	if obfuscatedJS.Code == "" {
		if err := c.generateAndCacheChallengeJS(context.Background()); err != nil {
			return "", fmt.Errorf("failed to generate challenge JS: %w", err)
		}
		obfuscatedJS = c.getLibraryBundle()
		if obfuscatedJS.Code == "" {
			return "", fmt.Errorf("challenge JS cache is empty")
		}
	}

	// Issuance is stateless (only submission is stateful — see the single-use
	// burn in ValidateChallengeResponse). `r` seeds the per-challenge secret
	// `s = HMAC(K_epoch, r)` the client derives from the obfuscated dynamic
	// module, so `s` never appears in plain HTML; the PoW MAC binds the salt to
	// `r`+ts so a client can't pick a favourable salt.
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	r, err := generateChallengeNonce()
	if err != nil {
		return "", err
	}
	powSalt, err := generatePowPrefix()
	if err != nil {
		return "", fmt.Errorf("generate PoW salt: %w", err)
	}
	powMAC := c.computePowMAC(powSalt, r, ts)

	if c.log().Logger.IsLevelEnabled(log.DebugLevel) {
		issEpoch, issKey := c.keys.Current()
		c.log().WithFields(log.Fields{
			"r":          r,
			"epoch":      issEpoch,
			"k_epoch":    fmt.Sprintf("%x", issKey),
			"difficulty": difficulty,
		}).Debug("issued challenge")
	}

	// The static bundle only carries the hook registration; the dynamic module
	// carries the per-epoch K, so K never appears in plain HTML.
	dynamicModule, err := c.currentDynamicModule(context.Background())
	if err != nil {
		return "", fmt.Errorf("build dynamic key module: %w", err)
	}

	var renderedPage strings.Builder

	if err := c.htmlTpl.Execute(&renderedPage, map[string]interface{}{
		"JSChallenge":   obfuscatedJS.Code,
		"DynamicModule": dynamicModule,
		"PowDifficulty": difficulty,
		"PowPrefix":     powSalt,
		"PowMAC":        powMAC,
		"Timestamp":     ts,
		"R":             r,
	}); err != nil {
		return "", fmt.Errorf("render challenge page: %w", err)
	}
	return renderedPage.String(), nil
}

// ValidateChallengeResponse parses a submit POST and runs the full chain:
// freshness + PoW-salt authenticity, PoW solution, the submission signature
// `sig` (keyed by the never-transmitted s = HMAC(K_epoch, r)), a single-use
// burn of `r` (replay protection), and fingerprint de-obfuscation. On success
// it returns the sealed cookie and decoded FingerprintData; failures return a
// generic error so the caller doesn't leak which stage failed.
func (c *ChallengeRuntime) ValidateChallengeResponse(request *http.Request, body []byte) (*cookie.AppsecCookie, FingerprintData, error) {
	vars, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to parse challenge response: %w", err)
	}

	encryptedFingerprint := vars.Get("f")
	clientR := vars.Get("r")
	clientTS := vars.Get("ts")
	clientSig := vars.Get("sig")
	clientNonce := vars.Get("n")
	clientPowSalt := vars.Get("p")
	clientPowMAC := vars.Get("m")

	if encryptedFingerprint == "" || clientR == "" || clientTS == "" || clientSig == "" || clientNonce == "" || clientPowSalt == "" || clientPowMAC == "" {
		return nil, FingerprintData{}, fmt.Errorf("missing required fields in challenge response")
	}

	// Verify freshness + PoW-salt authenticity and recover the per-epoch sign
	// key (stateless). Key knowledge is proven by `sig` below.
	signKey, ok := c.verifyChallenge(clientR, clientTS, clientPowSalt, clientPowMAC)
	if !ok {
		return nil, FingerprintData{}, fmt.Errorf("invalid ticket in challenge response")
	}

	// Impossible difficulty is a deliberate hard-block: never accept anything.
	if c.powDifficulty >= PowDifficultyImpossible {
		return nil, FingerprintData{}, fmt.Errorf("challenge difficulty is impossible; submission rejected")
	}

	// Verify proof-of-work: SHA256(powSalt + nonce) must have required leading zero bits
	powHash := sha256.Sum256([]byte(clientPowSalt + clientNonce))
	if !hasLeadingZeroBits(powHash[:], c.powDifficulty) {
		return nil, FingerprintData{}, fmt.Errorf("invalid proof-of-work in challenge response")
	}

	// Verify the submission signature sig = HMAC(s, r||ts||n||f), where the
	// secret s = HMAC(K_epoch, r) is never transmitted — a valid sig proves the
	// client derived s from the per-epoch key in the obfuscated dynamic module.
	s := deriveChallengeSecret(signKey, clientR)

	expectedSig := hmacSHA256Hex([]byte(s), []byte(clientR+clientTS+clientNonce+encryptedFingerprint))
	if !hmac.Equal([]byte(clientSig), []byte(expectedSig)) {
		return nil, FingerprintData{}, fmt.Errorf("invalid HMAC in challenge response")
	}

	// Single-use: burn `r` (rejects replays). Done last so the spent-set only
	// grows on fully-valid submissions.
	if !c.spent.checkAndInsert(clientR, ticketAgeBackstop) {
		return nil, FingerprintData{}, fmt.Errorf("challenge response already used")
	}

	obfKey := deriveFingerprintObfKey(s, clientR)

	fingerprint, err := deobfuscateFingerprint(obfKey, encryptedFingerprint)
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to deobfuscate fingerprint: %w", err)
	}

	var fpData FingerprintData

	if err := json.Unmarshal([]byte(fingerprint), &fpData); err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to unmarshal fingerprint data: %w", err)
	}

	// Debug diagnostic: a validated submission. Guarded so `k_epoch` (forgeable
	// signing material — DESIGN.md §2.1) is only formatted at debug.
	if c.log().Logger.IsLevelEnabled(log.DebugLevel) {
		c.log().WithFields(log.Fields{
			"r":       clientR,
			"epoch":   c.epochForTimestamp(clientTS),
			"k_epoch": fmt.Sprintf("%x", signKey),
			"fsid":    fpData.FSID,
			"is_bot":  fpData.FastBotDetection,
		}).Debug("validated submission")
	}

	envelope := &pb.ChallengeCookie{
		Fingerprint:   fpData.ToProto(),
		PowDifficulty: int32(c.powDifficulty),
	}

	// Seal under the long-lived master cookie key. The embedded not_after makes
	// the server validity window exactly c.cookieTTL (independent of key
	// rotation); the browser Max-Age below matches so both expire together.
	notAfter := time.Now().Add(c.cookieTTL).Unix()
	cookieValue, err := sealCookieV0(envelope, c.keys.MasterCookieKey(), notAfter, 0, "", []byte(request.UserAgent()))
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to seal challenge cookie: %w", err)
	}

	ck := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite(cookie.SameSiteLax).ExpiresIn(c.cookieTTL).Value(cookieValue)
	if request.URL.Scheme == "https" {
		ck = ck.Secure()
	}

	return ck, fpData, nil
}

// SealAllowlistCookie mints an allowlist-bypass cookie (no fingerprint, with
// the operator reason) so GrantChallengeCookie can let trusted bots skip the
// challenge UI while still hitting on_challenge rules via fingerprint.Allowlisted.
// not_after honors c.cookieTTL unless ttlOverride (>0) is given; reason is
// bounded by MaxAllowlistReasonLen (crypto.go).
func (c *ChallengeRuntime) SealAllowlistCookie(request *http.Request, reason string, ttlOverride *time.Duration) (*cookie.AppsecCookie, error) {
	if c == nil {
		return nil, fmt.Errorf("challenge runtime not initialized")
	}

	ttl := c.cookieTTL
	if ttlOverride != nil && *ttlOverride > 0 {
		ttl = *ttlOverride
	}

	notAfter := time.Now().Add(ttl).Unix()
	cookieValue, err := sealCookieV0(&pb.ChallengeCookie{}, c.keys.MasterCookieKey(), notAfter, cookieFlagAllowlisted, reason, []byte(request.UserAgent()))
	if err != nil {
		return nil, fmt.Errorf("failed to seal allowlist cookie: %w", err)
	}

	ck := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite(cookie.SameSiteLax).ExpiresIn(ttl).Value(cookieValue)
	if request.URL.Scheme == "https" {
		ck = ck.Secure()
	}

	return ck, nil
}

// CookieData bundles the decoded fingerprint with cookie-envelope metadata for
// re-challenge decisions. Allowlisted/AllowlistReason mark cookies minted by
// SealAllowlistCookie; they are zero for real-submission cookies.
type CookieData struct {
	Fingerprint     FingerprintData
	PowDifficulty   int
	Allowlisted     bool
	AllowlistReason string
}

// ValidCookie unseals and validates a challenge cookie: envelope (version,
// AES-GCM tag), not_after expiry, and UA-pinning (a stolen cookie is useless to
// a different client). On any failure (tampered/expired/UA-mismatch/unknown
// version) it returns an error and the caller should treat the request as
// cookieless.
func (c *ChallengeRuntime) ValidCookie(ck *http.Cookie, userAgent string) (*CookieData, error) {
	if ck == nil {
		return nil, fmt.Errorf("nil cookie")
	}

	envelope, err := openCookie(ck.Value, c.keys.MasterCookieKey(), []byte(userAgent))
	if err != nil {
		return nil, fmt.Errorf("invalid challenge cookie: %w", err)
	}

	return &CookieData{
		Fingerprint:     fingerprintDataFromProto(envelope.Envelope.GetFingerprint()),
		PowDifficulty:   int(envelope.Envelope.GetPowDifficulty()),
		Allowlisted:     envelope.Allowlisted,
		AllowlistReason: envelope.AllowlistReason,
	}, nil
}
