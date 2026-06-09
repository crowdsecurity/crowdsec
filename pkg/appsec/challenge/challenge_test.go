package challenge

import (
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

func TestDeriveChallengeSecret(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	keys, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)
	c := &ChallengeRuntime{keys: keys}

	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	epoch := c.epochForTimestamp(ts)
	signKey, ok := c.keys.SignKey(epoch)
	require.True(t, ok)

	r1, err := generateChallengeNonce()
	require.NoError(t, err)
	r2, err := generateChallengeNonce()
	require.NoError(t, err)

	s1 := deriveChallengeSecret(signKey, r1)
	s1again := deriveChallengeSecret(signKey, r1)
	s2 := deriveChallengeSecret(signKey, r2)

	assert.Len(t, s1, 64)         // HMAC-SHA256 hex
	assert.Equal(t, s1, s1again)  // deterministic in (signKey, r)
	assert.NotEqual(t, s1, s2)    // distinct per-challenge r → distinct s

	// Matches HMAC-SHA256 under the per-epoch sign key.
	assert.Equal(t, hmacSHA256Hex(signKey, []byte(r1)), s1)

	// The fingerprint obfuscation key is derived from s and r, distinct from s.
	obf := deriveFingerprintObfKey(s1, r1)
	assert.Len(t, obf, 64)
	assert.NotEqual(t, s1, obf)
	assert.Equal(t, obf, deriveFingerprintObfKey(s1, r1)) // deterministic
}

func TestVerifyChallenge(t *testing.T) {
	keys, err := NewKeyRing([]byte("0123456789abcdef0123456789abcdef"), time.Minute, 3)
	require.NoError(t, err)
	c := &ChallengeRuntime{keys: keys}

	r, ts := freshChallenge(t)
	salt := mustGeneratePowPrefix(t)
	mac := c.computePowMAC(salt, r, ts)

	// Valid challenge → returns the epoch sign key.
	signKey, ok := c.verifyChallenge(r, ts, salt, mac)
	assert.True(t, ok)
	assert.NotEmpty(t, signKey)

	// Wrong r (MAC bound to a different r).
	_, ok = c.verifyChallenge("ffffffffffffffffffffffffffffffff", ts, salt, mac)
	assert.False(t, ok)

	// Malformed timestamp.
	_, ok = c.verifyChallenge(r, "9999999999999999999", salt, mac)
	assert.False(t, ok)

	// Forged MAC.
	_, ok = c.verifyChallenge(r, ts, salt, "forged-mac")
	assert.False(t, ok)

	// MAC from a different salt.
	otherSalt := mustGeneratePowPrefix(t)
	_, ok = c.verifyChallenge(r, ts, otherSalt, mac)
	assert.False(t, ok)

	// Expired timestamp (too old).
	oldTS := fmt.Sprintf("%d", time.Now().Add(-3*ticketAgeBackstop).UnixNano())
	oldMAC := c.computePowMAC(salt, r, oldTS)
	_, ok = c.verifyChallenge(r, oldTS, salt, oldMAC)
	assert.False(t, ok)

	// Cross-secret rejection: a challenge signed by a different master secret
	// must NOT validate.
	otherKeys, err := NewKeyRing([]byte("ffffffffffffffffffffffffffffffff"), time.Minute, 3)
	require.NoError(t, err)
	other := &ChallengeRuntime{keys: otherKeys}
	otherMAC := other.computePowMAC(salt, r, ts)
	_, ok = c.verifyChallenge(r, ts, salt, otherMAC)
	assert.False(t, ok)
}

// TestDistributedAgreement asserts that two ChallengeRuntime instances
// configured with the same master_secret derive bit-identical per-challenge
// secrets and PoW MACs — the property that makes load-balanced deployments
// work (challenge issuance is stateless; only the spent-set is local).
func TestDistributedAgreement(t *testing.T) {
	secret := []byte("shared-secret-shared-secret-shar") // 32 bytes
	keysA, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)
	keysB, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)
	a := &ChallengeRuntime{keys: keysA}
	b := &ChallengeRuntime{keys: keysB}

	r, ts := freshChallenge(t)
	salt := "deadbeefcafebabe"

	// Both instances agree on the PoW MAC...
	assert.Equal(t, a.computePowMAC(salt, r, ts), b.computePowMAC(salt, r, ts))

	// ...and on the per-challenge secret derived from the epoch for ts.
	epoch := a.epochForTimestamp(ts)
	keyA, ok := a.keys.SignKey(epoch)
	require.True(t, ok)
	keyB, ok := b.keys.SignKey(epoch)
	require.True(t, ok)
	assert.Equal(t, deriveChallengeSecret(keyA, r), deriveChallengeSecret(keyB, r))

	// And a challenge issued by A validates against B.
	signKey, ok := b.verifyChallenge(r, ts, salt, a.computePowMAC(salt, r, ts))
	assert.True(t, ok)
	assert.NotEmpty(t, signKey)
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
// runtimes via NewChallengeRuntime). Includes a spent-set so
// ValidateChallengeResponse's single-use burn works.
func newTestRuntime() *ChallengeRuntime {
	return &ChallengeRuntime{keys: testKeyRing(), spent: newSpentSet(spentSetDefaultMaxEntries)}
}

// newTestRuntimeWithDifficulty is a small convenience for the many ValidateChallengeResponse tests.
func newTestRuntimeWithDifficulty(d int) *ChallengeRuntime {
	return &ChallengeRuntime{keys: testKeyRing(), powDifficulty: d, spent: newSpentSet(spentSetDefaultMaxEntries)}
}

// freshChallenge generates a per-request nonce+timestamp pair (matching
// GetChallengePage's `r` and `ts`).
func freshChallenge(tb testing.TB) (r, ts string) {
	tb.Helper()
	ts = fmt.Sprintf("%d", time.Now().UnixNano())
	var err error
	r, err = generateChallengeNonce()
	require.NoError(tb, err)
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
func buildValidBody(tb testing.TB, difficulty int, r, ts string) string {
	return buildValidBodyWithFingerprint(tb, difficulty, r, ts, FingerprintData{})
}

// buildValidBodyWithFingerprint mirrors buildValidBody but lets the caller
// supply a populated FingerprintData so tests can assert that the submitted
// payload survives the full obfuscate → sign → deobfuscate → unmarshal chain.
// It mirrors the client (challenge.js): derive s = HMAC(K_epoch, r), obfuscate
// f under HMAC(s, "fpenc"||r), and sign sig = HMAC(s, r||ts||n||f).
func buildValidBodyWithFingerprint(tb testing.TB, difficulty int, r, ts string, fp FingerprintData) string {
	c := newTestRuntime()
	salt := mustGeneratePowPrefix(tb)
	powMAC := c.computePowMAC(salt, r, ts)
	nonce := solvePoWGo(salt, difficulty)

	// Derive s exactly as the server will, from the per-epoch sign key for ts.
	// Mirror computePowMAC's fallback for out-of-window timestamps (used by the
	// expired-timestamp test) so the body is still constructible; the server
	// rejects on freshness before the signature is ever checked.
	epoch := c.epochForTimestamp(ts)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		_, signKey = c.keys.Current()
	}
	s := deriveChallengeSecret(signKey, r)

	fpJSON, err := json.Marshal(fp)
	require.NoError(tb, err)

	obfKey := deriveFingerprintObfKey(s, r)
	keyBytes := []byte(obfKey)
	obfuscated := make([]byte, len(fpJSON))
	for i := range fpJSON {
		obfuscated[i] = fpJSON[i] ^ keyBytes[i%len(keyBytes)]
	}
	f := base64.StdEncoding.EncodeToString(obfuscated)

	sig := hmacSHA256Hex([]byte(s), []byte(r+ts+nonce+f))

	return url.Values{
		"f":   {f},
		"r":   {r},
		"ts":  {ts},
		"sig": {sig},
		"n":   {nonce},
		"p":   {salt},
		"m":   {powMAC},
	}.Encode()
}

func TestValidateChallengeResponse(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	r, ts := freshChallenge(t)
	body := buildValidBody(t, c.powDifficulty, r, ts)

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	ck, fpResult, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	assert.NotNil(t, ck)
	assert.NotNil(t, fpResult)
}

// TestValidateChallengeResponse_Replay asserts single-use: a valid submission
// is accepted once, and re-submitting the identical body is rejected because
// its per-challenge nonce `r` has been burned.
func TestValidateChallengeResponse_Replay(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	r, ts := freshChallenge(t)
	body := buildValidBody(t, c.powDifficulty, r, ts)

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)

	// Replay the exact same body — must be rejected as already used.
	req2, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req2.Header.Set("User-Agent", "test-agent")
	_, _, err = c.ValidateChallengeResponse(req2, []byte(body))
	assert.ErrorContains(t, err, "already used")
}

// TestValidateChallengeResponse_FingerprintRoundTrip is the explicit
// happy-path guard for the full client→server seal/unseal chain. Other
// ValidateChallengeResponse tests only assert that a well-formed submission
// is accepted; this one verifies that the FingerprintData the browser
// submits is the same FingerprintData the server gets back, then survives
// the cookie Seal → Open round-trip too. Regression guard for any future
// change to encryption, HMAC keying, or proto conversion.
func TestValidateChallengeResponse_FingerprintRoundTrip(t *testing.T) {
	c := &ChallengeRuntime{keys: testKeyRing(), powDifficulty: 8, cookieTTL: time.Hour, spent: newSpentSet(spentSetDefaultMaxEntries)}

	submitted := FingerprintData{
		FSID:             "fsid-abcdef",
		Nonce:            "client-nonce-xyz",
		Time:             1700000000,
		URL:              "https://example.com/protected",
		FastBotDetection: FlexBool(false),
	}

	r, ts := freshChallenge(t)
	body := buildValidBodyWithFingerprint(t, c.powDifficulty, r, ts, submitted)

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
		r, ts := freshChallenge(t)
		body := buildValidBody(t, c.powDifficulty, r, ts)
		req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
		req.Header.Set("User-Agent", "test-agent")

		_, _, err := c.ValidateChallengeResponse(req, []byte(body))
		require.NoError(t, err)
	}
}

func TestValidateChallengeResponse_InvalidPoW(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	r, ts := freshChallenge(t)
	salt := mustGeneratePowPrefix(t)
	powMAC := c.computePowMAC(salt, r, ts)

	body := url.Values{
		"f":   {"dGVzdA=="},
		"r":   {r},
		"ts":  {ts},
		"sig": {"deadbeef"},
		"n":   {"invalid-nonce"},
		"p":   {salt},
		"m":   {powMAC},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid proof-of-work")
}

func TestValidateChallengeResponse_ImpossibleDifficulty(t *testing.T) {
	// A submission that would otherwise pass at low difficulty is rejected
	// outright when the runtime is set to impossible.
	c := newTestRuntimeWithDifficulty(PowDifficultyImpossible)
	r, ts := freshChallenge(t)
	body := buildValidBody(t, 8, r, ts) // satisfies 8-bit PoW but not impossible

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "impossible")
}

func TestValidateChallengeResponse_ExpiredTimestamp(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	r, _ := freshChallenge(t)
	oldTS := fmt.Sprintf("%d", time.Now().Add(-3*ticketAgeBackstop).UnixNano())
	body := buildValidBody(t, c.powDifficulty, r, oldTS)

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid ticket")
}

// TestValidateChallengeResponse_TamperedR sends a different `r` than the one
// the PoW MAC was issued for, so verifyChallenge's MAC check fails.
func TestValidateChallengeResponse_TamperedR(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	r, ts := freshChallenge(t)
	salt := mustGeneratePowPrefix(t)
	powMAC := c.computePowMAC(salt, r, ts) // bound to r, not to the tampered value

	body := url.Values{
		"f":   {"dGVzdA=="},
		"r":   {"ffffffffffffffffffffffffffffffff"},
		"ts":  {ts},
		"sig": {"deadbeef"},
		"n":   {"0"},
		"p":   {salt},
		"m":   {powMAC},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid ticket")
}

func TestValidateChallengeResponse_ForgedMAC(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	r, ts := freshChallenge(t)
	salt := mustGeneratePowPrefix(t)

	body := url.Values{
		"f":   {"dGVzdA=="},
		"r":   {r},
		"ts":  {ts},
		"sig": {"deadbeef"},
		"n":   {"0"},
		"p":   {salt},
		"m":   {"forged-mac-value"},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid ticket")
}

func TestValidateChallengeResponse_InvalidSig(t *testing.T) {
	c := newTestRuntimeWithDifficulty(8)
	r, ts := freshChallenge(t)
	salt := mustGeneratePowPrefix(t)
	powMAC := c.computePowMAC(salt, r, ts)
	nonce := solvePoWGo(salt, c.powDifficulty)

	body := url.Values{
		"f":   {"dGVzdA=="},
		"r":   {r},
		"ts":  {ts},
		"sig": {"0000000000000000000000000000000000000000000000000000000000000000"},
		"n":   {nonce},
		"p":   {salt},
		"m":   {powMAC},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid HMAC")
}

func TestValidateChallengeResponse_MissingFields(t *testing.T) {
	c := &ChallengeRuntime{}

	body := url.Values{
		"f": {"dGVzdA=="},
		"r": {"abcd"},
	}.Encode()

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "missing required fields")
}
