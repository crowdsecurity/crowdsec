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
	p1 := generatePowPrefix()
	p2 := generatePowPrefix()

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
	c := &ChallengeRuntime{powDifficulty: defaultPowDifficulty}

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
	// Deterministic for same timestamp
	t1 := computeTicket("12345")
	t2 := computeTicket("12345")
	assert.Equal(t, t1, t2)

	// Different for different timestamps
	t3 := computeTicket("67890")
	assert.NotEqual(t, t1, t3)

	// Matches expected HMAC-SHA256
	h := hmac.New(sha256.New, []byte(masterSecret))
	h.Write([]byte("12345"))
	assert.Equal(t, fmt.Sprintf("%x", h.Sum(nil)), t1)
}

func TestMatchesChallenge(t *testing.T) {
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	ticket := computeTicket(ts)
	salt := generatePowPrefix()
	mac := computePowMAC(salt, ticket, ts)

	// Valid challenge
	assert.True(t, matchesChallenge(ticket, ts, salt, mac))

	// Wrong ticket
	assert.False(t, matchesChallenge("wrong-ticket", ts, salt, mac))

	// Wrong timestamp (ticket doesn't match)
	assert.False(t, matchesChallenge(ticket, "9999999999999999999", salt, mac))

	// Forged MAC
	assert.False(t, matchesChallenge(ticket, ts, salt, "forged-mac"))

	// MAC from different salt
	otherSalt := generatePowPrefix()
	assert.False(t, matchesChallenge(ticket, ts, otherSalt, mac))

	// Expired timestamp (too old)
	oldTS := fmt.Sprintf("%d", time.Now().Add(-3*challengeJSRefreshInterval).UnixNano())
	oldTicket := computeTicket(oldTS)
	oldMAC := computePowMAC(salt, oldTicket, oldTS)
	assert.False(t, matchesChallenge(oldTicket, oldTS, salt, oldMAC))
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
	prefix := generatePowPrefix()
	difficulty := 8

	nonce := solvePoWGo(prefix, difficulty)

	powHash := sha256.Sum256([]byte(prefix + nonce))
	assert.True(t, hasLeadingZeroBits(powHash[:], difficulty))
}

// freshTicket generates a per-request ticket+timestamp pair (matching GetChallengePage).
func freshTicket() (ticket, ts string) {
	ts = fmt.Sprintf("%d", time.Now().UnixNano())
	ticket = computeTicket(ts)
	return
}

// buildValidBody constructs a valid challenge POST body.
func buildValidBody(difficulty int, ticket, ts string) string {
	c := &ChallengeRuntime{}
	salt := generatePowPrefix()
	powMAC := computePowMAC(salt, ticket, ts)
	nonce := solvePoWGo(salt, difficulty)
	sessionKey := c.getSessionKey(ticket, nonce)

	fp := FingerprintData{}
	fpJSON, _ := json.Marshal(fp)

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
	c := &ChallengeRuntime{powDifficulty: 8}
	ticket, ts := freshTicket()
	body := buildValidBody(c.powDifficulty, ticket, ts)

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	ck, fpResult, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	assert.NotNil(t, ck)
	assert.NotNil(t, fpResult)
}

func TestValidateChallengeResponse_MultipleConcurrentClients(t *testing.T) {
	c := &ChallengeRuntime{powDifficulty: 8}

	for range 20 {
		ticket, ts := freshTicket()
		body := buildValidBody(c.powDifficulty, ticket, ts)
		req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
		req.Header.Set("User-Agent", "test-agent")

		_, _, err := c.ValidateChallengeResponse(req, []byte(body))
		require.NoError(t, err)
	}
}

func TestValidateChallengeResponse_InvalidPoW(t *testing.T) {
	c := &ChallengeRuntime{powDifficulty: 8}
	ticket, ts := freshTicket()
	salt := generatePowPrefix()
	powMAC := computePowMAC(salt, ticket, ts)

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
	c := &ChallengeRuntime{powDifficulty: PowDifficultyImpossible}
	ticket, ts := freshTicket()
	body := buildValidBody(8, ticket, ts) // satisfies 8-bit PoW but not impossible

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "impossible")
}

func TestValidateChallengeResponse_ExpiredTimestamp(t *testing.T) {
	c := &ChallengeRuntime{powDifficulty: 8}
	oldTS := fmt.Sprintf("%d", time.Now().Add(-3*challengeJSRefreshInterval).UnixNano())
	oldTicket := computeTicket(oldTS)
	body := buildValidBody(c.powDifficulty, oldTicket, oldTS)

	req, _ := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")

	_, _, err := c.ValidateChallengeResponse(req, []byte(body))
	assert.ErrorContains(t, err, "invalid ticket")
}

func TestValidateChallengeResponse_InvalidTicket(t *testing.T) {
	c := &ChallengeRuntime{powDifficulty: 8}
	ticket, ts := freshTicket()
	salt := generatePowPrefix()
	powMAC := computePowMAC(salt, ticket, ts)

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
	c := &ChallengeRuntime{powDifficulty: 8}
	ticket, ts := freshTicket()
	salt := generatePowPrefix()

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
	c := &ChallengeRuntime{powDifficulty: 8}
	ticket, ts := freshTicket()
	salt := generatePowPrefix()
	powMAC := computePowMAC(salt, ticket, ts)
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
