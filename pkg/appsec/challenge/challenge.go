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
	log "github.com/sirupsen/logrus"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"golang.org/x/sync/singleflight"
)

const ChallengeJSPath = "/crowdsec-internal/challenge/challenge.js"
const ChallengeSubmitPath = "/crowdsec-internal/challenge/submit"
const ChallengePowWorkerPath = "/crowdsec-internal/challenge/pow-worker.js"
const ChallengeCookieName = "__crowdsec_challenge"

// libraryBundlePoolDefaultSize is the default ceiling for the library
// bundle pool. The library bundle is always obfuscated at build time
// (initial_bundle.js.gz); with runtime obfuscation off (the default), the
// pool only ever contains that single baked-in variant — so a default of
// 1 matches reality. With runtime obfuscation enabled
// (WithLibraryRuntimeObfuscationEnabled), this becomes the steady-state
// ceiling that the background refresher trickles new variants into.
const libraryBundlePoolDefaultSize = 1

// libraryBundleRefreshDefaultInterval is the default cadence at which a
// single new library-bundle variant is obfuscated and added to the pool
// (oldest evicted) when runtime library obfuscation is enabled. One
// obfuscation per tick regardless of pool size — full pool rotation
// takes pool_size × refresh_interval.
const libraryBundleRefreshDefaultInterval = time.Hour

// cryptoObfuscationPoolDefaultSize is the default number of distinct
// obfuscations of the per-epoch sign-key module to keep per live epoch.
// Each variant is an obfuscation of the *same* key material, so the
// pool gives per-visitor variance in how the key is embedded without
// changing the underlying key. Default 1 preserves the historical
// single-variant-per-epoch behaviour.
const cryptoObfuscationPoolDefaultSize = 1

// defaultCookieTTL is how long a successful challenge cookie is valid by
// default. Decoupled from the keyring rotation window: an operator can
// configure long cookies (e.g. 24h) without widening the ticket-forgery
// exposure window (keyring live window, default 15m).
const defaultCookieTTL = 12 * time.Hour

const DefaultChallengeCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; worker-src 'self' blob:;"

//go:embed challenge.html.tmpl
var htmlTemplate string

// grantRedirectBody is served as the body of the 307 challenge response
// produced by GrantChallengeCookie. The browser follows the Location
// header without ever rendering this; it is a no-JS fallback for
// hand-rolled HTTP clients that don't auto-redirect. Static (no
// per-request data) so no parsing is needed.
//
//go:embed grant_redirect.html.tmpl
var GrantRedirectBody string

//go:embed pow-worker.js
var PowWorkerJS string

type ChallengeRuntime struct {
	r             wazero.Runtime
	obfuscatorMod wazero.CompiledModule

	// libraryRuntimeObfuscationEnabled gates the background pool refresher
	// for the library bundle. The library bundle is ALWAYS obfuscated at
	// build time (initial_bundle.js.gz); when this flag is false (the
	// default), the runtime serves only that baked-in variant and the
	// refresher goroutine is not spawned — no runtime obfuscator cost for
	// the static bundle in steady state. When true,
	// libraryBundlePoolRefresher trickles in one new runtime-obfuscated
	// variant per tick.
	libraryRuntimeObfuscationEnabled bool
	libraryPoolSize                  int
	libraryRefreshInterval           time.Duration

	// libraryBundlePool holds up to libraryPoolSize obfuscated variants of
	// the static library bundle (fpscanner / PoW worker glue). Always seeded
	// at startup with the baked-in initial_bundle.js.gz. When library
	// obfuscation is enabled, the refresher goroutine appends new variants
	// and trims oldest entries past libraryPoolSize. The serving path picks
	// one variant at random per challenge render for per-visitor byte
	// variance.
	libraryBundlePool   []obfuscatedScript
	libraryBundlePoolMu sync.RWMutex

	powDifficulty int

	// keys derives per-epoch sign keys (HMAC for tickets / PoW MACs) and the
	// long-lived master cookie key from the configured master secret. All
	// HMAC and AEAD operations route through this so that ticket rotation
	// is a server-side bookkeeping change with no protocol impact. In
	// distributed setups, every WAF instance with the same master_secret
	// and rotation_interval derives bit-identical keys.
	keys *KeyRing

	// cryptoPoolSize is the number of distinct obfuscations of the per-epoch
	// sign-key module to keep per live epoch. Each variant obfuscates the
	// *same* key material differently, so the pool gives per-visitor byte
	// variance in how the key is embedded without changing the underlying
	// secret. Default cryptoObfuscationPoolDefaultSize (1) preserves the
	// historical single-variant-per-epoch behaviour.
	cryptoPoolSize int

	// dynamicModuleCache memoizes the obfuscated per-epoch key module
	// variants. Each epoch maps to a slice of cryptoPoolSize obfuscated
	// renderings of the same epoch key — currentDynamicModule picks one at
	// random per render.
	//
	// dynamicModuleSF de-duplicates concurrent obfuscation requests for the
	// same epoch+variant slot: if N requests hit a freshly-rotated epoch
	// simultaneously, only one runs the obfuscator per slot and the others
	// wait for its result. The cache mutex is only held for the fast
	// read/write of the map, never across the multi-second obfuscation
	// pass, so concurrent requests at a rotation boundary observe at most
	// one obfuscation latency per slot rather than N serialized ones.
	dynamicModuleCache   map[int64][]string
	dynamicModuleCacheMu sync.RWMutex
	dynamicModuleSF      singleflight.Group

	// cookieTTL controls how long a successful-challenge cookie remains
	// valid. Enforced by an explicit not_after timestamp inside the
	// sealed envelope (see crypto.go), NOT by keyring eviction, so it
	// can be much larger than the ticket-signing live window.
	cookieTTL time.Duration

	// htmlTpl is the parsed challenge HTML template. Parsed once at
	// construction and reused by every GetChallengePage call so we don't
	// re-parse on the request-serving path.
	htmlTpl *template.Template
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

// WithCookieTTL sets how long an issued challenge cookie remains valid.
// Decoupled from the per-epoch keyring window so cookies can be long-lived
// (e.g. 24h) while ticket-signing keys still rotate on a tight schedule.
// Zero or negative values are ignored (defaultCookieTTL is used).
func WithCookieTTL(ttl time.Duration) Option {
	return func(o *runtimeOptions) {
		if ttl > 0 {
			o.cookieTTL = ttl
		}
	}
}

// WithCryptoObfuscationPoolSize sets how many distinct obfuscations of
// the per-epoch sign-key module to keep per live epoch. Each variant
// obfuscates the same key material; the serving path picks one at
// random per challenge render for per-visitor byte variance. Default 1
// (cryptoObfuscationPoolDefaultSize) preserves the historical
// single-variant-per-epoch behaviour. Values below 1 are ignored.
func WithCryptoObfuscationPoolSize(n int) Option {
	return func(o *runtimeOptions) {
		if n >= 1 {
			o.cryptoObfuscationPoolSize = n
		}
	}
}

// WithLibraryRuntimeObfuscationEnabled gates the background re-obfuscation
// of the static library bundle (fpscanner, PoW worker glue) at runtime.
// The bundle is ALWAYS obfuscated at build time; this flag only controls
// whether additional runtime-generated variants are produced. Off by
// default — the runtime serves only the baked-in obfuscated bundle and
// pays no runtime obfuscator cost for the static path. Enable only if you
// want per-visitor byte variance on top of the build-time obfuscation for
// the public library code.
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
		log.Warnf("library_obfuscation_pool_size=%d ignored: library_runtime_obfuscation_enabled is false, only the baked-in variant will populate the pool. Clamping to 1.", libraryPoolSize)
		libraryPoolSize = 1
	}

	libraryRefreshInterval := resolvedOpts.libraryObfuscationRefreshInterval
	if libraryRefreshInterval <= 0 {
		libraryRefreshInterval = libraryBundleRefreshDefaultInterval
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
	if _, err := challengeRuntime.currentDynamicModule(ctx); err != nil {
		return nil, fmt.Errorf("warm dynamic key module: %w", err)
	}

	// The library-bundle refresher is gated on opt-in: the static bundle is
	// public code (the source is in the repo) and the baked-in obfuscated
	// variant is already served at request time, so runtime regeneration
	// only buys per-visitor byte variance on top of build-time obfuscation
	// and is not worth its ~minute-of-CPU-per-obfuscation cost by default.
	if resolvedOpts.libraryRuntimeObfuscationEnabled {
		go challengeRuntime.libraryBundlePoolRefresher(ctx)
	}
	// The dynamic-module pre-warmer is always on — the per-epoch sign key
	// must be re-obfuscated whenever the keyring rotates, regardless of
	// the library-side pool config. Cost is bounded (one obfuscation per
	// epoch per pool variant, default 1).
	go challengeRuntime.dynamicModulePreWarmer(ctx)

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

	// All per-request values: timestamp, PoW salt, PoW MAC.
	// Fully stateless — no server-side storage, works across HA instances.
	//
	// The client recomputes the ticket itself from the per-epoch key
	// embedded in the dynamic key module (so the signing material never
	// appears in plain HTML). The server-side ticket here is only used to
	// bind the PoW salt to ts via computePowMAC.
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	ticket := c.computeTicket(ts)
	powSalt, err := generatePowPrefix()
	if err != nil {
		return "", fmt.Errorf("generate PoW salt: %w", err)
	}
	powMAC := c.computePowMAC(powSalt, ticket, ts)

	// Build and (cheaply) obfuscate the dynamic key module for the current
	// epoch. The static bundle in obfuscatedJS.Code only carries the hook
	// registration; the dynamic module is what carries the per-epoch K — so
	// K never appears in plain HTML.
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
	}); err != nil {
		return "", fmt.Errorf("render challenge page: %w", err)
	}
	return renderedPage.String(), nil
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

	log.Errorf("challenge response: %s", fingerprint)

	var fpData FingerprintData

	if err := json.Unmarshal([]byte(fingerprint), &fpData); err != nil {
		log.Errorf("fp: %s", fingerprint)
		return nil, FingerprintData{}, fmt.Errorf("failed to unmarshal fingerprint data: %w", err)
	}

	envelope := &pb.ChallengeCookie{
		Fingerprint:   fpData.ToProto(),
		PowDifficulty: int32(c.powDifficulty),
	}

	// Seal under the long-lived master cookie key; the sealed envelope
	// embeds an explicit not_after timestamp so the server-side validity
	// window is exactly c.cookieTTL, independent of the keyring's per-
	// epoch rotation cadence. The browser-side Max-Age below is set to
	// the same TTL so the browser drops the cookie at the same moment.
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

// SealAllowlistCookie mints an allowlist-bypass challenge cookie carrying
// no measured fingerprint and the operator-supplied reason. Used by the
// GrantChallengeCookie expr helper to let trusted bots (Googlebot, …)
// skip the challenge UI while still being subject to on_challenge rules
// (which can short-circuit on fingerprint.Allowlisted).
//
// The cookie's not_after honors c.cookieTTL by default; pass a non-nil
// ttlOverride (must be > 0) to use a different validity window for this
// specific cookie. The browser-side Max-Age and the sealed not_after are
// derived from the same effective TTL so they stay in sync.
//
// reason is bounded by MaxAllowlistReasonLen (crypto.go) — longer strings
// are rejected with ErrAllowlistReasonSize.
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

// CookieData bundles the decrypted fingerprint with cookie-envelope metadata
// so callers can make re-challenge decisions without touching the fingerprint
// struct.
//
// Allowlisted and AllowlistReason carry the operator-bypass marker for
// cookies minted by SealAllowlistCookie; they are zero for cookies issued
// after a real challenge submission.
type CookieData struct {
	Fingerprint     FingerprintData
	PowDifficulty   int
	Allowlisted     bool
	AllowlistReason string
}

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
