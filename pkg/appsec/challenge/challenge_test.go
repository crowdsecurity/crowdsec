package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasLeadingZeroBits(t *testing.T) {
	tests := []struct {
		name   string
		hash   []byte
		bits   int
		expect bool
	}{
		{
			name:   "0 bits required",
			hash:   []byte{0xff, 0xff},
			bits:   0,
			expect: true,
		},
		{
			name:   "8 bits - first byte zero",
			hash:   []byte{0x00, 0xff},
			bits:   8,
			expect: true,
		},
		{
			name:   "8 bits - first byte not zero",
			hash:   []byte{0x01, 0xff},
			bits:   8,
			expect: false,
		},
		{
			name:   "16 bits - two zero bytes",
			hash:   []byte{0x00, 0x00, 0xff},
			bits:   16,
			expect: true,
		},
		{
			name:   "10 bits - partial byte check passes",
			hash:   []byte{0x00, 0x20}, // 0b00000000 0b00100000 → 10 leading zeros
			bits:   10,
			expect: true,
		},
		{
			name:   "10 bits - partial byte check fails",
			hash:   []byte{0x00, 0x40}, // 0b00000000 0b01000000 → 9 leading zeros
			bits:   10,
			expect: false,
		},
		{
			name:   "1 bit - first bit zero",
			hash:   []byte{0x7f},
			bits:   1,
			expect: true,
		},
		{
			name:   "1 bit - first bit set",
			hash:   []byte{0x80},
			bits:   1,
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, hasLeadingZeroBits(tt.hash, tt.bits))
		})
	}
}

func TestGeneratePowPrefix(t *testing.T) {
	p1 := mustGeneratePowPrefix(t)
	p2 := mustGeneratePowPrefix(t)

	assert.Len(t, p1, 32) // 16 bytes = 32 hex chars
	assert.Len(t, p2, 32)
	assert.NotEqual(t, p1, p2) // random, should differ
}

func TestDifficultyFromLevel(t *testing.T) {
	bits, err := DifficultyFromLevel("low")
	assert.NoError(t, err)
	assert.Equal(t, PowDifficultyLow, bits)

	bits, err = DifficultyFromLevel("MEDIUM")
	assert.NoError(t, err)
	assert.Equal(t, PowDifficultyMedium, bits)

	bits, err = DifficultyFromLevel("High")
	assert.NoError(t, err)
	assert.Equal(t, PowDifficultyHigh, bits)

	bits, err = DifficultyFromLevel("disabled")
	assert.NoError(t, err)
	assert.Equal(t, PowDifficultyDisabled, bits)

	bits, err = DifficultyFromLevel("IMPOSSIBLE")
	assert.NoError(t, err)
	assert.Equal(t, PowDifficultyImpossible, bits)

	_, err = DifficultyFromLevel("extreme")
	assert.Error(t, err)
}

func TestSetDifficulty(t *testing.T) {
	c := newTestRuntimeWithDifficulty(defaultPowDifficulty)

	assert.NoError(t, c.SetDifficulty("low"))
	assert.Equal(t, PowDifficultyLow, c.powDifficulty)

	assert.NoError(t, c.SetDifficulty("MEDIUM"))
	assert.Equal(t, PowDifficultyMedium, c.powDifficulty)

	assert.NoError(t, c.SetDifficulty("High"))
	assert.Equal(t, PowDifficultyHigh, c.powDifficulty)

	assert.NoError(t, c.SetDifficulty("impossible"))
	assert.Equal(t, PowDifficultyImpossible, c.powDifficulty)

	assert.Error(t, c.SetDifficulty("extreme"))
	assert.Equal(t, PowDifficultyImpossible, c.powDifficulty) // unchanged on error
}

func TestGetSessionKey(t *testing.T) {
	c := &ChallengeRuntime{}

	key1 := c.getSessionKey("ticket1", "nonce1")
	key2 := c.getSessionKey("ticket1", "nonce2")
	key3 := c.getSessionKey("ticket1", "nonce1")

	assert.Len(t, key1, 64) // SHA-256 = 64 hex chars
	assert.NotEqual(t, key1, key2)
	assert.Equal(t, key1, key3) // deterministic

	expected := sha256.Sum256([]byte("ticket1nonce1"))
	assert.Equal(t, fmt.Sprintf("%x", expected), key1)
}

func TestComputeTicket(t *testing.T) {
	// Use a fixed test secret so the HMAC equality check is reproducible.
	secret := []byte("0123456789abcdef0123456789abcdef")
	keys, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)
	c := &ChallengeRuntime{keys: keys}

	// Use a current timestamp so the keyring derives the right epoch.
	ts1 := fmt.Sprintf("%d", time.Now().UnixNano())

	// Deterministic for same timestamp
	t1 := c.computeTicket(ts1)
	t2 := c.computeTicket(ts1)
	assert.Equal(t, t1, t2)

	// Different for different timestamps
	ts2 := fmt.Sprintf("%d", time.Now().Add(2*time.Second).UnixNano())
	t3 := c.computeTicket(ts2)
	assert.NotEqual(t, t1, t3)

	// Matches HMAC-SHA256 under the per-epoch sign key for ts1's epoch.
	epoch := c.epochForTimestamp(ts1)
	signKey, ok := c.keys.SignKey(epoch)
	require.True(t, ok)
	h := hmac.New(sha256.New, signKey)
	h.Write([]byte(ts1))
	assert.Equal(t, fmt.Sprintf("%x", h.Sum(nil)), t1)
}

func TestMatchesChallenge(t *testing.T) {
	keys, err := NewKeyRing([]byte("0123456789abcdef0123456789abcdef"), time.Minute, 3)
	require.NoError(t, err)
	c := &ChallengeRuntime{keys: keys}

	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	ticket := c.computeTicket(ts)
	salt := mustGeneratePowPrefix(t)
	mac := c.computePowMAC(salt, ticket, ts)

	// Valid challenge
	assert.True(t, c.matchesChallenge(ticket, ts, salt, mac))

	// Wrong ticket
	assert.False(t, c.matchesChallenge("wrong-ticket", ts, salt, mac))

	// Wrong timestamp (ticket doesn't match)
	assert.False(t, c.matchesChallenge(ticket, "9999999999999999999", salt, mac))

	// Forged MAC
	assert.False(t, c.matchesChallenge(ticket, ts, salt, "forged-mac"))

	// MAC from different salt
	otherSalt := mustGeneratePowPrefix(t)
	assert.False(t, c.matchesChallenge(ticket, ts, otherSalt, mac))

	// Expired timestamp (too old)
	oldTS := fmt.Sprintf("%d", time.Now().Add(-3*ticketAgeBackstop).UnixNano())
	oldTicket := c.computeTicket(oldTS)
	oldMAC := c.computePowMAC(salt, oldTicket, oldTS)
	assert.False(t, c.matchesChallenge(oldTicket, oldTS, salt, oldMAC))

	// Cross-secret rejection: a ticket signed by a different instance with a
	// different master secret must NOT validate.
	otherKeys, err := NewKeyRing([]byte("ffffffffffffffffffffffffffffffff"), time.Minute, 3)
	require.NoError(t, err)
	other := &ChallengeRuntime{keys: otherKeys}
	otherTicket := other.computeTicket(ts)
	otherMAC := other.computePowMAC(salt, otherTicket, ts)
	assert.False(t, c.matchesChallenge(otherTicket, ts, salt, otherMAC))
}

// TestDistributedAgreement asserts that two ChallengeRuntime instances
// configured with the same master_secret produce bit-identical tickets and
// PoW MACs — the property that makes load-balanced deployments work.
func TestDistributedAgreement(t *testing.T) {
	secret := []byte("shared-secret-shared-secret-shar") // 32 bytes
	keysA, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)
	keysB, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)
	a := &ChallengeRuntime{keys: keysA}
	b := &ChallengeRuntime{keys: keysB}

	// Use a freshness-window-valid timestamp so matchesChallenge accepts it.
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	salt := "deadbeefcafebabe"

	assert.Equal(t, a.computeTicket(ts), b.computeTicket(ts))

	ticket := a.computeTicket(ts)
	assert.Equal(t, a.computePowMAC(salt, ticket, ts), b.computePowMAC(salt, ticket, ts))

	// And a challenge issued by A validates against B.
	assert.True(t, b.matchesChallenge(ticket, ts, salt, a.computePowMAC(salt, ticket, ts)))
}

// solvePoWGo is a Go implementation of the PoW solver matching the JS client.
func solvePoWGo(prefix string, difficulty int) string {
	for nonce := 0; ; nonce++ {
		candidate := prefix + formatBase36(nonce)
		hash := sha256.Sum256([]byte(candidate))
		if hasLeadingZeroBits(hash[:], difficulty) {
			return formatBase36(nonce)
		}
	}
}

func formatBase36(n int) string {
	if n == 0 {
		return "0"
	}

	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	var buf [64]byte
	i := len(buf)

	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}

	return string(buf[i:])
}

func TestPoWVerification(t *testing.T) {
	prefix := mustGeneratePowPrefix(t)
	difficulty := 8

	nonce := solvePoWGo(prefix, difficulty)

	powHash := sha256.Sum256([]byte(prefix + nonce))
	assert.True(t, hasLeadingZeroBits(powHash[:], difficulty))
}

// testSecret is a fixed master secret used by all test helpers below so that
// tickets / MACs / cookies issued in one helper validate in another.
var testSecret = []byte("test-secret-test-secret-test-sec") // 32 bytes

// testKeyRing returns a fresh KeyRing built around testSecret. Returned by
// value would defeat the cache, so we hand back a pointer and rely on the
// caller to discard it after the test.
func testKeyRing() *KeyRing {
	k, err := NewKeyRing(testSecret, time.Minute, 3)
	if err != nil {
		panic(err)
	}
	return k
}

// newTestRuntime returns a minimal ChallengeRuntime suitable for the helpers
// in this file (no WASM, no obfuscation cache — those tests construct full
// runtimes via NewChallengeRuntime).
func newTestRuntime() *ChallengeRuntime {
	return &ChallengeRuntime{keys: testKeyRing()}
}

// newTestRuntimeWithDifficulty is a small convenience for the many ValidateChallengeResponse tests.
func newTestRuntimeWithDifficulty(d int) *ChallengeRuntime {
	return &ChallengeRuntime{keys: testKeyRing(), powDifficulty: d}
}

// freshTicket generates a per-request ticket+timestamp pair (matching GetChallengePage).
func freshTicket() (ticket, ts string) {
	ts = fmt.Sprintf("%d", time.Now().UnixNano())
	ticket = newTestRuntime().computeTicket(ts)
	return
}

// mustGeneratePowPrefix is the test-only wrapper around generatePowPrefix
// that aborts the test if crypto/rand fails (which would mean the test
// machine is broken in a way that invalidates the run anyway).
func mustGeneratePowPrefix(tb testing.TB) string {
	tb.Helper()
	p, err := generatePowPrefix()
	require.NoError(tb, err)
	return p
}

// buildValidBody constructs a valid challenge POST body with an empty
// fingerprint. Existing tests rely on this signature; for tests that need
// to assert fingerprint round-trip through the seal/unseal chain, use
// buildValidBodyWithFingerprint.
func buildValidBody(tb testing.TB, difficulty int, ticket, ts string) string {
	return buildValidBodyWithFingerprint(tb, difficulty, ticket, ts, FingerprintData{})
}

// buildValidBodyWithFingerprint mirrors buildValidBody but lets the caller
// supply a populated FingerprintData so tests can assert that the submitted
// payload survives the full encrypt → HMAC → decrypt → unmarshal chain.
func buildValidBodyWithFingerprint(tb testing.TB, difficulty int, ticket, ts string, fp FingerprintData) string {
	c := newTestRuntime()
	salt := mustGeneratePowPrefix(tb)
	powMAC := c.computePowMAC(salt, ticket, ts)
	nonce := solvePoWGo(salt, difficulty)
	sessionKey := c.getSessionKey(ticket, nonce)

	fpJSON, err := json.Marshal(fp)
	require.NoError(tb, err)

	keyBytes := []byte(sessionKey)
	encrypted := make([]byte, len(fpJSON))
	for i := range fpJSON {
		encrypted[i] = fpJSON[i] ^ keyBytes[i%len(keyBytes)]
	}
	encryptedB64 := base64.StdEncoding.EncodeToString(encrypted)

	mac := hmac.New(sha256.New, []byte(sessionKey))
	mac.Write([]byte(encryptedB64))
	mac.Write([]byte(ts))
	mac.Write([]byte(ticket))
	mac.Write([]byte(nonce))
	hmacHex := fmt.Sprintf("%x", mac.Sum(nil))

	return url.Values{
		"f":  {encryptedB64},
		"t":  {ticket},
		"ts": {ts},
		"h":  {hmacHex},
		"n":  {nonce},
		"p":  {salt},
		"m":  {powMAC},
	}.Encode()
}

func TestValidateChallengeResponse(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	ticket, ts := freshTicket()
	body := buildValidBody(t, c.powDifficulty, ticket, ts)

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	ck, fpResult, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	assert.NotNil(t, ck)
	assert.NotNil(t, fpResult)
}

// TestValidateChallengeResponse_FingerprintRoundTrip is the explicit
// happy-path guard for the full client→server seal/unseal chain. Other
// ValidateChallengeResponse tests only assert that a well-formed submission
// is accepted; this one verifies that the FingerprintData the browser
// submits is the same FingerprintData the server gets back, then survives
// the cookie Seal → Open round-trip too. Regression guard for any future
// change to encryption, HMAC keying, or proto conversion.
func TestValidateChallengeResponse_FingerprintRoundTrip(t *testing.T) {
	c := &ChallengeRuntime{keys: testKeyRing(), powDifficulty: 8, cookieTTL: time.Hour}

	submitted := FingerprintData{
		FSID:             "fsid-abcdef",
		Nonce:            "client-nonce-xyz",
		Time:             1700000000,
		URL:              "https://example.com/protected",
		FastBotDetection: FlexBool(false),
	}

	ticket, ts := freshTicket()
	body := buildValidBodyWithFingerprint(t, c.powDifficulty, ticket, ts, submitted)

	req, err := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	ck, decoded, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, ck)

	// The fingerprint returned by ValidateChallengeResponse must match what
	// the browser submitted (XOR'd, base64'd, then decrypted server-side).
	assert.Equal(t, submitted.FSID, decoded.FSID)
	assert.Equal(t, submitted.Nonce, decoded.Nonce)
	assert.Equal(t, submitted.Time, decoded.Time)
	assert.Equal(t, submitted.URL, decoded.URL)

	// The sealed cookie must round-trip through ValidCookie and yield the
	// same fingerprint contents — guards the proto conversion + AES-GCM
	// seal/unseal chain.
	parsed, err := http.ParseSetCookie(ck.String())
	require.NoError(t, err)

	cd, err := c.ValidCookie(parsed, "test-agent")
	require.NoError(t, err)
	require.NotNil(t, cd)
	assert.Equal(t, submitted.FSID, cd.Fingerprint.FSID)
	assert.Equal(t, submitted.URL, cd.Fingerprint.URL)
	assert.Equal(t, c.powDifficulty, cd.PowDifficulty)
}

func TestValidateChallengeResponse_MultipleConcurrentClients(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)

	for range 20 {
		ticket, ts := freshTicket()
		body := buildValidBody(t, c.powDifficulty, ticket, ts)
		req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
		req.Header.Set("User-Agent", "test-agent")

		_, _, err := c.ValidateChallengeResponse(req, []byte(body))
		require.NoError(t, err)
	}
}

func TestValidateChallengeResponse_InvalidPoW(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	ticket, ts := freshTicket()
	salt := mustGeneratePowPrefix(t)
	powMAC := c.computePowMAC(salt, ticket, ts)

	body := url.Values{
		"f":  {"dGVzdA=="},
		"t":  {ticket},
		"ts": {ts},
		"h":  {"deadbeef"},
		"n":  {"invalid-nonce"},
		"p":  {salt},
		"m":  {powMAC},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid proof-of-work")
}

func TestValidateChallengeResponse_ImpossibleDifficulty(t *testing.T) {
	// A submission that would otherwise pass at low difficulty is rejected
	// outright when the runtime is set to impossible.
	c := newTestRuntimeWithDifficulty(PowDifficultyImpossible)
	ticket, ts := freshTicket()
	body := buildValidBody(t, 8, ticket, ts) // satisfies 8-bit PoW but not impossible

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "impossible")
}

func TestValidateChallengeResponse_ExpiredTimestamp(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	oldTS := fmt.Sprintf("%d", time.Now().Add(-3*ticketAgeBackstop).UnixNano())
	oldTicket := c.computeTicket(oldTS)
	body := buildValidBody(t, c.powDifficulty, oldTicket, oldTS)

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid ticket")
}

func TestValidateChallengeResponse_InvalidTicket(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	ticket, ts := freshTicket()
	salt := mustGeneratePowPrefix(t)
	powMAC := c.computePowMAC(salt, ticket, ts)

	body := url.Values{
		"f":  {"dGVzdA=="},
		"t":  {"wrong-ticket"},
		"ts": {ts},
		"h":  {"deadbeef"},
		"n":  {"0"},
		"p":  {salt},
		"m":  {powMAC},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid ticket")
}

func TestValidateChallengeResponse_ForgedMAC(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	ticket, ts := freshTicket()
	salt := mustGeneratePowPrefix(t)

	body := url.Values{
		"f":  {"dGVzdA=="},
		"t":  {ticket},
		"ts": {ts},
		"h":  {"deadbeef"},
		"n":  {"0"},
		"p":  {salt},
		"m":  {"forged-mac-value"},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid ticket")
}

func TestValidateChallengeResponse_InvalidHMAC(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	ticket, ts := freshTicket()
	salt := mustGeneratePowPrefix(t)
	powMAC := c.computePowMAC(salt, ticket, ts)
	nonce := solvePoWGo(salt, c.powDifficulty)

	body := url.Values{
		"f":  {"dGVzdA=="},
		"t":  {ticket},
		"ts": {ts},
		"h":  {"0000000000000000000000000000000000000000000000000000000000000000"},
		"n":  {nonce},
		"p":  {salt},
		"m":  {powMAC},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid HMAC")
}

func TestValidateChallengeResponse_MissingFields(t *testing.T) {
	c := &ChallengeRuntime{}

	body := url.Values{
		"f": {"dGVzdA=="},
		"t": {"ticket"},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "missing required fields")
}
