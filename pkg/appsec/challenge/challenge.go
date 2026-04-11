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
	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
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
	PowDifficultyDisabled = 0  // no PoW required, nonce "0" always valid
	PowDifficultyLow      = 10 // ~1024 avg iterations ≈ 0.2-2s
	PowDifficultyMedium   = 12 // ~4096 avg iterations ≈ 1-8s
	PowDifficultyHigh     = 15 // ~32768 avg iterations ≈ 7-60s

	defaultPowDifficulty = PowDifficultyMedium
)

// FIXME
const masterSecret = "SUPER_SECRET_KEY"

//go:embed challenge.html.tmpl
var htmlTemplate string

//go:embed pow-worker.js
var PowWorkerJS string

//go:embed js/obfuscate/index.wasm.gz
var obfuscatorWasmGz []byte

var (
	obfuscatorWasm     []byte
	obfuscatorWasmOnce sync.Once
)

type ChallengeRuntime struct {
	r wazero.Runtime

	obfuscatedJSCache []obfuscatedScript
	cacheMutex        sync.RWMutex

	powDifficulty int
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
	default:
		return 0, fmt.Errorf("unknown challenge difficulty %q (expected disabled, low, medium, or high)", level)
	}
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

func NewChallengeRuntime(ctx context.Context) (*ChallengeRuntime, error) {
	r := wazero.NewRuntime(ctx)

	// No need to keep the closer around, we can just close the runtime itself when stopping
	_, err := wasi_snapshot_preview1.Instantiate(ctx, r)
	if err != nil {
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

	challengeRuntime := &ChallengeRuntime{
		r:                 r,
		obfuscatedJSCache: make([]obfuscatedScript, 0, challengeJSCacheSize),
		powDifficulty:     defaultPowDifficulty,
	}

	if err := challengeRuntime.generateAndCacheChallengeJS(ctx); err != nil {
		return nil, fmt.Errorf("failed to generate initial challenge bundle: %w", err)
	}

	go challengeRuntime.challengeGenerator(ctx)

	return challengeRuntime, nil
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

	mod, err := c.r.InstantiateWithConfig(ctx, obfuscatorWasm, config)
	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("wasm runtime error: %v | stderr: %s", err, stderr.String())
		}
		return "", fmt.Errorf("wasm instantiation error: %v", err)
	}

	mod.Close(ctx)

	return stdout.String(), nil
}

func computeTicket(ts string) string {
	h := hmac.New(sha256.New, []byte(masterSecret))
	h.Write([]byte(ts))

	return fmt.Sprintf("%x", h.Sum(nil))
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

	// All per-request values: ticket, timestamp, PoW salt, PoW MAC.
	// Fully stateless — no server-side storage, works across HA instances.
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	ticket := computeTicket(ts)
	powSalt := generatePowPrefix()
	powMAC := computePowMAC(powSalt, ticket, ts)

	var renderedPage strings.Builder

	templateObj.Execute(&renderedPage, map[string]interface{}{
		"JSChallenge":   obfuscatedJS.Code,
		"PowDifficulty": difficulty,
		"PowPrefix":     powSalt,
		"PowMAC":        powMAC,
		"Ticket":        ticket,
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

// computePowMAC produces an HMAC that authenticates a PoW salt as server-generated
// and bound to a specific ticket window. Stateless: any instance sharing the
// masterSecret can verify it.
func computePowMAC(salt, ticket, ts string) string {
	h := hmac.New(sha256.New, []byte(masterSecret))
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
// sharing masterSecret can verify.
func matchesChallenge(clientTicket, clientTS, clientPowSalt, clientPowMAC string) bool {
	// Verify the ticket is an authentic HMAC of the timestamp.
	expectedTicket := computeTicket(clientTS)
	if !hmac.Equal([]byte(clientTicket), []byte(expectedTicket)) {
		return false
	}

	// Verify the timestamp is recent (within 2 refresh intervals for safety).
	tsVal, err := strconv.ParseInt(clientTS, 10, 64)
	if err != nil {
		return false
	}

	age := time.Since(time.Unix(0, tsVal))
	if age < 0 || age > 2*challengeJSRefreshInterval {
		return false
	}

	// Verify the PoW salt MAC is authentic and bound to this ticket+timestamp.
	expectedMAC := computePowMAC(clientPowSalt, clientTicket, clientTS)

	return hmac.Equal([]byte(clientPowMAC), []byte(expectedMAC))
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
	if !matchesChallenge(clientTicket, clientTS, clientPowSalt, clientPowMAC) {
		return nil, FingerprintData{}, fmt.Errorf("invalid ticket in challenge response")
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

	cookieValue, err := sealCookie(fpData.ToProto(), masterSecret, []byte(request.UserAgent()))
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to seal challenge cookie: %w", err)
	}

	ck := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite(cookie.SameSiteLax).ExpiresIn(2 * time.Hour).Value(cookieValue)
	if request.URL.Scheme == "https" {
		ck = ck.Secure()
	}

	return ck, fpData, nil
}

func (c *ChallengeRuntime) ValidCookie(ck *http.Cookie, userAgent string) (*FingerprintData, error) {
	if ck == nil {
		return nil, fmt.Errorf("nil cookie")
	}

	pbData, err := openCookie(ck.Value, masterSecret, []byte(userAgent))
	if err != nil {
		return nil, fmt.Errorf("invalid challenge cookie: %w", err)
	}

	fpData := fingerprintDataFromProto(pbData)

	return &fpData, nil
}
