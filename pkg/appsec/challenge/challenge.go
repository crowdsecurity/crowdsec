package challenge

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	log "github.com/sirupsen/logrus"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const ChallengeJSPath = "/crowdsec-internal/challenge/challenge.js"
const ChallengeSubmitPath = "/crowdsec-internal/challenge/submit"
const ChallengeCookieName = "__crowdsec_challenge"
const challengeJSCacheSize = 10
const challengeJSRefreshInterval = 10 * time.Minute

// FIXME
const masterSecret = "SUPER_SECRET_KEY"

//go:embed challenge.html.tmpl
var htmlTemplate string

//go:embed js/obfuscate/index.wasm.gz
var obfuscatorWasmGz []byte

var (
	obfuscatorWasm     []byte
	obfuscatorWasmOnce sync.Once
)

type ChallengeRuntime struct {
	r wazero.Runtime

	obfuscatedJSCache []string
	cacheMutex        sync.RWMutex

	challengeTicket    string
	challengeTimestamp string
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
		obfuscatedJSCache: make([]string, 0, challengeJSCacheSize),
	}

	challengeRuntime.challengeTimestamp = strconv.FormatInt(time.Now().UnixNano(), 10)
	challengeRuntime.challengeTicket = challengeRuntime.getTicket(challengeRuntime.challengeTimestamp)

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
		"__CROWDSEC_TICKET__", c.challengeTicket,
		"__CROWDSEC_TIMESTAMP__", c.challengeTimestamp,
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

func (c *ChallengeRuntime) generateChallengeVariants(ctx context.Context, count int) ([]string, error) {
	if count <= 0 {
		return []string{}, nil
	}

	bundle := c.buildChallengeBundle()
	variants := make([]string, 0, count)

	for range count {
		obfuscatedJS, err := c.ObfuscateJS(ctx, bundle)
		if err != nil {
			return nil, err
		}
		variants = append(variants, obfuscatedJS)
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

func (c *ChallengeRuntime) appendCachedChallengeJS(variants []string) {
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

func (c *ChallengeRuntime) replaceCachedChallengeJS(variants []string) {
	if len(variants) == 0 {
		return
	}

	c.cacheMutex.Lock()
	c.obfuscatedJSCache = append([]string(nil), variants...)
	c.cacheMutex.Unlock()
}

func (c *ChallengeRuntime) getCachedChallengeJS() string {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	cacheSize := len(c.obfuscatedJSCache)
	if cacheSize == 0 {
		return ""
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

	_, err := c.r.InstantiateWithConfig(ctx, obfuscatorWasm, config)
	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("wasm runtime error: %v | stderr: %s", err, stderr.String())
		}
		return "", fmt.Errorf("wasm instantiation error: %v", err)
	}

	return stdout.String(), nil
}

func (c *ChallengeRuntime) getTicket(ts string) string {
	if ts == "" {
		ts = strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	h := hmac.New(sha256.New, []byte(masterSecret))

	h.Write([]byte(ts))

	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c *ChallengeRuntime) GetChallengePage(userAgent string) (string, error) {
	_ = userAgent

	// We are using text/template instead of html/template because the data we send is pretty much hardcoded and trusted.
	// Using html/template would escape the JS code we are adding, making it unusable.
	templateObj, err := template.New("challenge").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse challenge template: %w", err)
	}

	obfuscatedJS := c.getCachedChallengeJS()
	if obfuscatedJS == "" {
		if err := c.generateAndCacheChallengeJS(context.Background()); err != nil {
			return "", fmt.Errorf("failed to generate challenge JS: %w", err)
		}
		obfuscatedJS = c.getCachedChallengeJS()
		if obfuscatedJS == "" {
			return "", fmt.Errorf("challenge JS cache is empty")
		}
	}

	var renderedPage strings.Builder

	templateObj.Execute(&renderedPage, map[string]string{
		"JSChallenge": obfuscatedJS,
	})
	return renderedPage.String(), nil
}

func (c *ChallengeRuntime) getSessionKey(ticket string) string {
	hash := sha256.Sum256([]byte(ticket))
	return fmt.Sprintf("%x", hash)
}

func (c *ChallengeRuntime) decryptFingerprint(sessionKey string, encrypted string) (string, error) {
	// Decode the base64-encoded encrypted fingerprint
	encryptedBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted fingerprint: %w", err)
	}

	decryptedBytes := make([]byte, len(encryptedBytes))

	for i := range encryptedBytes {
		decryptedBytes[i] = encryptedBytes[i] ^ sessionKey[i%len(sessionKey)]
	}

	decrypted := string(decryptedBytes)
	return decrypted, nil
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
	clientSessionKey := vars.Get("s")
	userAgent := request.UserAgent()

	if encryptedFingerprint == "" || clientTicket == "" || clientTS == "" || clientHMAC == "" || clientSessionKey == "" {
		return nil, FingerprintData{}, fmt.Errorf("missing required fields in challenge response")
	}

	if clientTicket != c.challengeTicket {
		return nil, FingerprintData{}, fmt.Errorf("invalid ticket in challenge response")
	}

	if clientTS != c.challengeTimestamp {
		return nil, FingerprintData{}, fmt.Errorf("invalid timestamp in challenge response")
	}

	sessionKey := c.getSessionKey(clientTicket)

	// If the key sent by the client is different from the one we just derived, something is wrong, drop the request.
	if sessionKey != clientSessionKey {
		log.Infof("Expected session key: %s | client session key: %s", sessionKey, clientSessionKey)
		return nil, FingerprintData{}, fmt.Errorf("invalid session key in challenge response")
	}

	// Now recompute the HMAC from encrypted fingerprint + timestamp + ticket

	expectedHMAC := hmac.New(sha256.New, []byte(sessionKey))

	expectedHMAC.Write([]byte(encryptedFingerprint))
	expectedHMAC.Write([]byte(clientTS))
	expectedHMAC.Write([]byte(clientTicket))

	expectedHMACB := fmt.Sprintf("%x", expectedHMAC.Sum(nil))

	if !hmac.Equal([]byte(clientHMAC), []byte(expectedHMACB)) {
		log.Infof("Expected HMAC: %s | Received HMAC: %s", expectedHMACB, clientHMAC)
		return nil, FingerprintData{}, fmt.Errorf("invalid HMAC in challenge response")
	}

	fingerprint, err := c.decryptFingerprint(sessionKey, encryptedFingerprint)
	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to decrypt fingerprint: %w", err)
	}

	var fpData FingerprintData

	err = json.Unmarshal([]byte(fingerprint), &fpData)

	if err != nil {
		return nil, FingerprintData{}, fmt.Errorf("failed to unmarshal fingerprint data: %w", err)
	}

	// FIXME: make this configurable
	//now := time.Now()

	// Would JWE be better and simpler here ?
	cookieHMAC := hmac.New(sha256.New, []byte(masterSecret))
	cookieHMAC.Write([]byte(userAgent))

	// Initial plan was to use expiration time as part of the HMAC
	// But it would also be part of the cookie, and the expiration time by itself is not sent by the client
	// So this means that we would need to partially trust some data from the cookie before validating it (and it would be used to derive the HMAC key), which seems bad.

	// Cookie value is encrypted value of {"iat": now, "f": fingerprint}
	// HMAC is computed with expiration time + user agent, so that the cookie is tied to both the client and a specific time window.

	cookieValue := fmt.Sprintf("%x", cookieHMAC.Sum(nil))

	ck := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite(cookie.SameSiteLax).ExpiresIn(2 * time.Hour).Value(cookieValue)
	if request.URL.Scheme == "https" {
		ck = ck.Secure()
	}
	return ck, fpData, nil
}

func (c *ChallengeRuntime) ValidCookie(cookie *http.Cookie) bool {
	if cookie == nil {
		return false
	}
	return true
}
