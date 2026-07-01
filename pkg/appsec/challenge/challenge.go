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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	ChallengeFPScannerPath = "/crowdsec-internal/challenge/fpscanner.js"
)

// Sentinel errors (reasons) returned by ValidateChallengeResponse.
var (
	ErrChallengeFields     = errors.New("missing required fields in challenge response")
	ErrChallengeTicket     = errors.New("invalid ticket in challenge response")
	ErrChallengeDifficulty = errors.New("challenge difficulty is impossible")
	ErrChallengePoW        = errors.New("invalid proof-of-work in challenge response")
	ErrChallengeHMAC       = errors.New("invalid HMAC in challenge response")
	ErrChallengePayload    = errors.New("invalid challenge response payload")
)

// ChallengeCookieName is the name of the sealed cookie carrying the
// successfully-validated fingerprint between requests.
const ChallengeCookieName = "__crowdsec_challenge"

// cryptoObfuscationPoolDefaultSize is how many obfuscations of the per-epoch
// key module to keep per live epoch. Each variant embeds the same key
// differently (per-visitor byte variance); default 1 keeps prior behavior.
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

	// challengeCode is the build-time-obfuscated challenge crypto/glue code,
	// decompressed once at startup from initial_bundle.js.gz and injected inline
	// on every challenge page. Static for the life of the process (no runtime
	// re-obfuscation or pool); the sensitive per-epoch key module lives in
	// dynamic_module.go.
	challengeCode string

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

	// maxCookieLen is the size ceiling enforced when sealing and opening cookies
	// (crypto.go). Bounds the allocation derived from the attacker-influenced
	// fingerprint envelope. Defaults to MaxCookieLen (the browser limit).
	maxCookieLen int

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

// Field semantics mirror the YAML Config in config.go;
type runtimeOptions struct {
	masterSecret              []byte // must be >= minSecretBytes when non-nil
	rotationInterval          time.Duration
	maxLiveEpochs             int
	cookieTTL                 time.Duration
	maxCookieLen              int
	cryptoObfuscationPoolSize int
	spentSetMaxEntries        int
	logger                    *log.Entry // nil → default "challenge" sublogger
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

// WithMasterSecret sets the long-lived shared secret (see Config.MasterSecret).
func WithMasterSecret(secret []byte) Option {
	return func(o *runtimeOptions) {
		o.masterSecret = secret
	}
}

// WithRotationInterval sets the per-epoch key rotation period (see Config.KeyRotationInterval).
func WithRotationInterval(d time.Duration) Option {
	return func(o *runtimeOptions) {
		o.rotationInterval = d
	}
}

// WithMaxLiveEpochs sets how many past epochs the keyring keeps accepting (see Config.MaxLiveEpochs).
func WithMaxLiveEpochs(n int) Option {
	return func(o *runtimeOptions) {
		o.maxLiveEpochs = n
	}
}

// WithCookieTTL sets challenge-cookie validity (see Config.CookieTTL); zero/negative is ignored.
func WithCookieTTL(ttl time.Duration) Option {
	return func(o *runtimeOptions) {
		if ttl > 0 {
			o.cookieTTL = ttl
		}
	}
}

// WithMaxCookieLen sets the cookie size ceiling (see Config.MaxCookieSize);
// zero/negative is ignored, leaving the MaxCookieLen default in effect.
func WithMaxCookieLen(n int) Option {
	return func(o *runtimeOptions) {
		if n > 0 {
			o.maxCookieLen = n
		}
	}
}

// WithCryptoObfuscationPoolSize sets the per-epoch sign-key obfuscation pool size
// (see Config.CryptoObfuscationPoolSize); values below 1 are ignored.
func WithCryptoObfuscationPoolSize(n int) Option {
	return func(o *runtimeOptions) {
		if n >= 1 {
			o.cryptoObfuscationPoolSize = n
		}
	}
}

// WithSpentSetMaxEntries caps the replay-protection LRU (see Config.SpentSetMaxEntries); values below 1 are ignored.
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

// NewChallengeRuntime builds and starts a ChallengeRuntime: it initializes the
// wazero runtime, decompresses the baked-in library bundle, derives the master
// secret + keyring, pre-warms the dynamic-module cache, and (if configured)
// spawns the background obfuscation refresher. Safe for concurrent use across
// all appsec runners. Pass WithXxx options to override defaults.
// compileObfuscatorModule decompresses the baked-in obfuscator WASM (once,
// process-wide) and compiles it for the given runtime. Pre-compiling lets each
// ObfuscateJS call merely instantiate the module instead of re-parsing the WASM
// bytes, which would otherwise cost ~4-5s per call.
func compileObfuscatorModule(ctx context.Context, r wazero.Runtime) (wazero.CompiledModule, error) {
	var obfuscatorWasmErr error

	obfuscatorWasmOnce.Do(func() {
		zr, err := gzip.NewReader(bytes.NewReader(obfuscatorWasmGz))
		if err != nil {
			obfuscatorWasmErr = fmt.Errorf("failed to create gzip reader for obfuscator wasm: %w", err)
			return
		}
		defer zr.Close()

		obfuscatorWasm, err = io.ReadAll(zr)
		if err != nil {
			obfuscatorWasmErr = fmt.Errorf("failed to decompress obfuscator wasm: %w", err)
			return
		}
	})

	if obfuscatorWasmErr != nil {
		return nil, obfuscatorWasmErr
	}

	compiledMod, err := r.CompileModule(ctx, obfuscatorWasm)
	if err != nil {
		return nil, fmt.Errorf("failed to compile obfuscator wasm module: %w", err)
	}

	return compiledMod, nil
}

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

	maxCookieLen := resolvedOpts.maxCookieLen
	if maxCookieLen <= 0 {
		maxCookieLen = MaxCookieLen
	}

	cryptoPoolSize := resolvedOpts.cryptoObfuscationPoolSize
	if cryptoPoolSize <= 0 {
		cryptoPoolSize = cryptoObfuscationPoolDefaultSize
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

	compiledMod, err := compileObfuscatorModule(ctx, r)
	if err != nil {
		return nil, err
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
		r:                  r,
		obfuscatorMod:      compiledMod,
		powDifficulty:      defaultPowDifficulty,
		keys:               keys,
		cryptoPoolSize:     cryptoPoolSize,
		dynamicModuleCache: make(map[int64][]string),
		cookieTTL:          cookieTTL,
		maxCookieLen:       maxCookieLen,
		htmlTpl:            htmlTpl,
		spent:              newSpentSet(spentSetMaxEntries),
		logger:             logger,
	}

	// Load the build-time-obfuscated challenge code from the baked-in bundle so
	// we can serve immediately.
	if err := challengeRuntime.seedCacheFromInitialBundle(); err != nil {
		// Initial bundle missing/corrupt (e.g. `go generate` not run): fall back
		// to obfuscating the challenge code synchronously.
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

	// The dynamic-module pre-warmer is always on — the per-epoch key must be
	// re-obfuscated on every rotation (bounded cost, one pass per variant). The
	// challenge code itself is static (build-time obfuscated), so there is no
	// library refresher anymore.
	go challengeRuntime.dynamicModulePreWarmer(ctx)

	logger.WithFields(log.Fields{
		"rotation_interval": rotationInterval,
		"cookie_ttl":        cookieTTL,
		"max_cookie_len":    maxCookieLen,
		"pow_difficulty":    defaultPowDifficulty,
		"crypto_pool_size":  cryptoPoolSize,
	}).Info("WAF challenge runtime initialized")

	return challengeRuntime, nil
}

func (c *ChallengeRuntime) Close(ctx context.Context) error {
	if c == nil || c.r == nil {
		return nil
	}
	return c.r.Close(ctx)
}

// GetChallengePage renders the challenge HTML page with the given PoW difficulty.
// If difficulty is 0, the default difficulty is used.
func (c *ChallengeRuntime) GetChallengePage(ctx context.Context, userAgent string, difficulty int) (string, error) {
	_ = userAgent

	if difficulty <= 0 {
		difficulty = c.powDifficulty
	}

	challengeCode := c.getChallengeCode()
	if challengeCode == "" {
		if err := c.generateAndCacheChallengeJS(ctx); err != nil {
			return "", fmt.Errorf("failed to generate challenge JS: %w", err)
		}
		challengeCode = c.getChallengeCode()
		if challengeCode == "" {
			return "", errors.New("challenge JS cache is empty")
		}
	}

	// Issuance is stateless (only submission is stateful — see the single-use
	// burn in ValidateChallengeResponse). `r` seeds the per-challenge secret
	// `s = HMAC(K_epoch, r)` the client derives from the obfuscated dynamic
	// module, so `s` never appears in plain HTML; the PoW MAC binds the salt to
	// `r`+ts so a client can't pick a favorable salt.
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	r, err := generateChallengeNonce()
	if err != nil {
		return "", err
	}
	powSalt, err := generatePowPrefix()
	if err != nil {
		return "", fmt.Errorf("generate PoW salt: %w", err)
	}
	powMAC := c.computePowMAC(powSalt, r, ts, difficulty)

	if c.log().Logger.IsLevelEnabled(log.DebugLevel) {
		issEpoch, issKey := c.keys.Current()
		c.log().WithFields(log.Fields{
			"r":          r,
			"epoch":      issEpoch,
			"k_epoch":    fmt.Sprintf("%x", issKey),
			"difficulty": difficulty,
		}).Debug("issued challenge")
	}

	// The challenge code only carries the hook registration; the dynamic module
	// carries the per-epoch K, so K never appears in plain HTML.
	dynamicModule, err := c.currentDynamicModule(ctx)
	if err != nil {
		return "", fmt.Errorf("build dynamic key module: %w", err)
	}

	var renderedPage strings.Builder

	if err := c.htmlTpl.Execute(&renderedPage, map[string]interface{}{
		"JSChallenge":   challengeCode,
		"DynamicModule": dynamicModule,
		"FPScannerPath": ChallengeFPScannerPath,
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
// freshness + PoW-salt authenticity + difficulty, PoW solution,
// the submission signature `sig` (keyed by the never-transmitted s = HMAC(K_epoch, r)),
// a single-use burn of `r` (replay protection),
// and fingerprint de-obfuscation. On success it returns the sealed
// cookie, decoded FingerprintData, and the proven PoW difficulty; failures
// return a generic error so the caller doesn't leak which stage failed.
func (c *ChallengeRuntime) ValidateChallengeResponse(request *http.Request, body []byte) (*cookie.AppsecCookie, FingerprintData, int, error) {
	vars, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, FingerprintData{}, 0, fmt.Errorf("%w: %w", ErrChallengePayload, err)
	}

	encryptedFingerprint := vars.Get("f")
	clientR := vars.Get("r")
	clientTS := vars.Get("ts")
	clientSig := vars.Get("sig")
	clientNonce := vars.Get("n")
	clientPowSalt := vars.Get("p")
	clientPowMAC := vars.Get("m")
	clientDifficultyStr := vars.Get("d")
	clientPath := vars.Get("u")

	if encryptedFingerprint == "" || clientR == "" || clientTS == "" || clientSig == "" || clientNonce == "" || clientPowSalt == "" || clientPowMAC == "" || clientDifficultyStr == "" || clientPath == "" {
		return nil, FingerprintData{}, 0, errors.New("missing required fields in challenge response")
	}

	// Override the request path so the WAF sees the original URL the client
	request.URL.Path = clientPath

	// The difficulty the client claims it solved. It is untrusted until the PoW
	// MAC (which binds it) is verified in verifyChallenge below. Bound to the
	// valid PoW range so a malformed value can't reach the PoW/seal logic.
	clientDifficulty, err := strconv.Atoi(clientDifficultyStr)
	if err != nil || clientDifficulty < PowDifficultyDisabled || clientDifficulty > PowDifficultyImpossible {
		return nil, FingerprintData{}, 0, errors.New("invalid ticket in challenge response")
	}

	// Server-issued `r` is a 16-byte nonce in hex (generateChallengeNonce):
	// exactly 32 hex chars. Reject other shapes early so a K_epoch holder can't
	// bloat the spent-set with oversized keys, and to keep the key space canonical.
	if _, err := hex.DecodeString(clientR); err != nil || len(clientR) != 32 {
		return nil, FingerprintData{}, 0, errors.New("invalid ticket in challenge response")
	}

	// Verify freshness + PoW-salt/difficulty authenticity and recover the
	// per-epoch sign key (stateless). Key knowledge is proven by `sig` below.
	signKey, ok := c.verifyChallenge(clientR, clientTS, clientPowSalt, clientPowMAC, clientDifficulty)
	if !ok {
		return nil, FingerprintData{}, 0, errors.New("invalid ticket in challenge response")
	}

	// Impossible difficulty is a deliberate hard-block: never accept anything.
	// clientDifficulty is now MAC-authenticated, so this enforces the difficulty
	// actually issued for this request, not the runtime-global default.
	if clientDifficulty >= PowDifficultyImpossible {
		return nil, FingerprintData{}, 0, ErrChallengeDifficulty
	}

	// Verify proof-of-work: SHA256(powSalt + nonce) must have required leading zero bits
	powHash := sha256.Sum256([]byte(clientPowSalt + clientNonce))
	if !hasLeadingZeroBits(powHash[:], clientDifficulty) {
		return nil, FingerprintData{}, 0, ErrChallengePoW
	}

	// Verify the submission signature sig = HMAC(s, r||ts||n||f), where the
	// secret s = HMAC(K_epoch, r) is never transmitted — a valid sig proves the
	// client derived s from the per-epoch key in the obfuscated dynamic module.
	s := deriveChallengeSecret(signKey, clientR)

	expectedSig := hmacSHA256Hex([]byte(s), []byte(clientR+clientTS+clientNonce+encryptedFingerprint))
	if !hmac.Equal([]byte(clientSig), []byte(expectedSig)) {
		return nil, FingerprintData{}, 0, errors.New("invalid HMAC in challenge response")
	}

	// Single-use: burn `r` (rejects replays). Done last so the spent-set only
	// grows on fully-valid submissions.
	if !c.spent.checkAndInsert(clientR, ticketAgeBackstop) {
		return nil, FingerprintData{}, 0, errors.New("challenge response already used")
	}

	obfKey := deriveFingerprintObfKey(s, clientR)

	fingerprint, err := deobfuscateFingerprint(obfKey, encryptedFingerprint)
	if err != nil {
		return nil, FingerprintData{}, 0, fmt.Errorf("failed to deobfuscate fingerprint: %w", err)
	}

	var fpData FingerprintData

	if err := json.Unmarshal([]byte(fingerprint), &fpData); err != nil {
		return nil, FingerprintData{}, 0, fmt.Errorf("%w: failed to unmarshal fingerprint data: %w", ErrChallengePayload, err)
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

	// Seal the difficulty the client actually proved (MAC-authenticated above),
	// so the next request's re-challenge check compares against real work and an
	// escalated per-request difficulty survives the cookie round-trip.
	envelope := &pb.ChallengeCookie{
		Fingerprint:   fpData.ToProto(),
		PowDifficulty: int32(clientDifficulty),
	}

	// Seal under the long-lived master cookie key. The embedded not_after makes
	// the server validity window exactly c.cookieTTL (independent of key
	// rotation); the browser Max-Age below matches so both expire together.
	notAfter := time.Now().Add(c.cookieTTL).Unix()
	cookieValue, err := sealCookieV0(envelope, c.keys.MasterCookieKey(), notAfter, 0, "", []byte(request.UserAgent()), c.maxCookieLen)
	if err != nil {
		return nil, FingerprintData{}, 0, fmt.Errorf("failed to seal challenge cookie: %w", err)
	}

	ck := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite(cookie.SameSiteLax).ExpiresIn(c.cookieTTL).Value(cookieValue)
	if request.URL.Scheme == "https" {
		ck = ck.Secure()
	}

	return ck, fpData, clientDifficulty, nil
}

// SealAllowlistCookie mints an allowlist-bypass cookie (no fingerprint, with
// the operator reason) so GrantChallengeCookie can let trusted bots skip the
// challenge UI while still hitting on_challenge rules via fingerprint.Allowlisted.
// not_after honors c.cookieTTL unless ttlOverride (>0) is given; reason is
// bounded by MaxAllowlistReasonLen (crypto.go).
func (c *ChallengeRuntime) SealAllowlistCookie(request *http.Request, reason string, ttlOverride *time.Duration) (*cookie.AppsecCookie, error) {
	if c == nil {
		return nil, errors.New("challenge runtime not initialized")
	}

	ttl := c.cookieTTL
	if ttlOverride != nil && *ttlOverride > 0 {
		ttl = *ttlOverride
	}

	notAfter := time.Now().Add(ttl).Unix()
	cookieValue, err := sealCookieV0(&pb.ChallengeCookie{}, c.keys.MasterCookieKey(), notAfter, cookieFlagAllowlisted, reason, []byte(request.UserAgent()), c.maxCookieLen)
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
		return nil, errors.New("nil cookie")
	}

	envelope, err := openCookie(ck.Value, c.keys.MasterCookieKey(), []byte(userAgent), c.maxCookieLen)
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
