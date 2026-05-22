package challenge

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCookieV0_RoundTrip is the basic positive case: seal under the master
// cookie key with an explicit not_after one hour in the future, open
// immediately, fingerprint comes back.
func TestCookieV0_RoundTrip(t *testing.T) {
	keys := testKeyRing()
	envelope := &pb.ChallengeCookie{PowDifficulty: 12}
	notAfter := time.Now().Add(time.Hour).Unix()

	encoded, err := sealCookieV0(envelope, keys.MasterCookieKey(), notAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	got, err := openCookie(encoded, keys.MasterCookieKey(), []byte("ua"))
	require.NoError(t, err)
	assert.Equal(t, int32(12), got.Envelope.GetPowDifficulty())
}

// TestCookieV0_ExpiredRejected confirms the not_after timestamp embedded
// inside the encrypted envelope is enforced on open.
func TestCookieV0_ExpiredRejected(t *testing.T) {
	keys := testKeyRing()

	// notAfter is one hour in the past — the cookie was already expired
	// when issued (this is what a stale cookie sent by a slow client would
	// look like on the server).
	pastNotAfter := time.Now().Add(-time.Hour).Unix()
	encoded, err := sealCookieV0(&pb.ChallengeCookie{}, keys.MasterCookieKey(), pastNotAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	_, err = openCookie(encoded, keys.MasterCookieKey(), []byte("ua"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCookieExpired,
		"expired cookie must produce ErrCookieExpired, got %v", err)
}

// TestCookieV0_TamperedExpirationRejected is the security-critical test for
// the design choice of putting not_after INSIDE the encrypted envelope. Any
// flip of a byte in the ciphertext (including bytes covering the not_after
// header) must invalidate the AEAD tag, not just shift the apparent
// expiration time.
func TestCookieV0_TamperedExpirationRejected(t *testing.T) {
	keys := testKeyRing()
	notAfter := time.Now().Add(time.Hour).Unix()

	encoded, err := sealCookieV0(&pb.ChallengeCookie{}, keys.MasterCookieKey(), notAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Wire layout: version(1) || nonce(12) || ciphertext(...)
	// The first byte of ciphertext corresponds to the first byte of
	// plaintext, which is the high byte of not_after_be8. Flipping it
	// MUST invalidate the AEAD tag.
	tampered := append([]byte(nil), raw...)
	tampered[1+12] ^= 0x80 // flip MSB of not_after's high byte
	tamperedEncoded := base64.RawURLEncoding.EncodeToString(tampered)

	_, err = openCookie(tamperedEncoded, keys.MasterCookieKey(), []byte("ua"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCookieSignature,
		"tampering with the not_after region must produce ErrCookieSignature (AEAD tag failure)")
}

// TestCookieV0_UAMismatchRejected confirms the User-Agent AAD binding.
func TestCookieV0_UAMismatchRejected(t *testing.T) {
	keys := testKeyRing()
	notAfter := time.Now().Add(time.Hour).Unix()

	encoded, err := sealCookieV0(&pb.ChallengeCookie{}, keys.MasterCookieKey(), notAfter, 0, "", []byte("ua-A"))
	require.NoError(t, err)

	_, err = openCookie(encoded, keys.MasterCookieKey(), []byte("ua-B"))
	assert.ErrorIs(t, err, ErrCookieSignature)
}

// TestCookieV0_SurvivesArbitraryRotation is the headline test for the v0
// design: a cookie sealed under the long-lived master cookie key remains
// valid across as many ticket-signing-key rotations as the keyring goes
// through. The previous design tied cookie validity to the same live
// window as ticket signing; this one decouples them completely.
//
// We advance the keyring's clock (forcing it to derive a stream of new
// epoch signing keys) and confirm that openCookie — which depends only
// on the master cookie key, not on any epoch — keeps working.
func TestCookieV0_SurvivesArbitraryRotation(t *testing.T) {
	t0 := time.Now()
	keys := newTestKeyRing(t, testSecret, time.Minute, t0)

	// notAfter is well in the future from real wall-clock time, so the
	// in-envelope expiration check (which uses real time.Now()) won't
	// reject the cookie.
	notAfter := t0.Add(24 * time.Hour).Unix()
	encoded, err := sealCookieV0(&pb.ChallengeCookie{PowDifficulty: 9}, keys.MasterCookieKey(), notAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	// Roll the keyring's clock forward — this triggers per-epoch sign-key
	// derivations and (with maxLive=3) evictions. None of that affects
	// the master cookie key, so the cookie keeps validating.
	for _, advance := range []time.Duration{
		1 * time.Minute,
		10 * time.Minute,
		1 * time.Hour,
		6 * time.Hour,
		23 * time.Hour,
	} {
		keys.now = func() time.Time { return t0.Add(advance) }

		// Touching keys.Current() forces a derivation under the new
		// keyring time, simulating real rotation activity.
		_, _ = keys.Current()

		got, err := openCookie(encoded, keys.MasterCookieKey(), []byte("ua"))
		require.NoError(t, err,
			"cookie should still validate after %s of keyring rotation; got %v", advance, err)
		assert.Equal(t, int32(9), got.Envelope.GetPowDifficulty())
	}
}

// TestCookieV0_ExpiryEnforcedAgainstWallClock is the counterpart to the
// rotation test: cookie expiration uses real wall-clock time (not the
// keyring's overridable now), so we seal a cookie with notAfter already
// in the past and confirm rejection.
func TestCookieV0_ExpiryEnforcedAgainstWallClock(t *testing.T) {
	keys := testKeyRing()

	pastNotAfter := time.Now().Add(-time.Minute).Unix()
	encoded, err := sealCookieV0(&pb.ChallengeCookie{}, keys.MasterCookieKey(), pastNotAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	_, err = openCookie(encoded, keys.MasterCookieKey(), []byte("ua"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCookieExpired)
}

// TestCookieV0_MasterSecretChangeInvalidates is the expected counter-property
// to SurvivesArbitraryRotation: if the operator rotates the master secret
// (a manual config change), every outstanding cookie is invalidated.
func TestCookieV0_MasterSecretChangeInvalidates(t *testing.T) {
	notAfter := time.Now().Add(time.Hour).Unix()

	keysA, err := NewKeyRing(bytes.Repeat([]byte{0xaa}, 32), time.Minute, 3)
	require.NoError(t, err)
	keysB, err := NewKeyRing(bytes.Repeat([]byte{0xbb}, 32), time.Minute, 3)
	require.NoError(t, err)

	encoded, err := sealCookieV0(&pb.ChallengeCookie{}, keysA.MasterCookieKey(), notAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	_, err = openCookie(encoded, keysB.MasterCookieKey(), []byte("ua"))
	assert.ErrorIs(t, err, ErrCookieSignature,
		"cookie sealed under secret A must not decrypt under secret B")
}

// TestCookieV0_DistributedSetup_TwoInstances confirms cookies issued by
// instance A validate against instance B as long as both share the same
// master secret. This is the multi-WAF deployment invariant.
func TestCookieV0_DistributedSetup_TwoInstances(t *testing.T) {
	secret := bytes.Repeat([]byte{0xcc}, 32)
	a, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)
	b, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(a.MasterCookieKey(), b.MasterCookieKey()),
		"two instances with the same master_secret must derive the same master cookie key")

	notAfter := time.Now().Add(time.Hour).Unix()
	encoded, err := sealCookieV0(&pb.ChallengeCookie{PowDifficulty: 14}, a.MasterCookieKey(), notAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	got, err := openCookie(encoded, b.MasterCookieKey(), []byte("ua"))
	require.NoError(t, err, "cookie issued by A must validate against B (same master_secret)")
	assert.Equal(t, int32(14), got.Envelope.GetPowDifficulty())
}

// TestCookie_UnknownVersionRejected makes the version-byte dispatch
// explicit: a cookie with an unknown leading byte is rejected with the
// dedicated ErrCookieVersion sentinel. This is the extension point for
// any future cookie schema bump.
func TestCookie_UnknownVersionRejected(t *testing.T) {
	keys := testKeyRing()

	// Forge: version byte 0xFE followed by random-looking junk.
	raw := append([]byte{0xFE}, []byte("0123456789abcdefghijklmnop")...)
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	_, err := openCookie(encoded, keys.MasterCookieKey(), []byte("ua"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCookieVersion, "unknown version byte must produce ErrCookieVersion")
}

// TestRotation_TicketSurvives_WithinLiveWindow exercises the most important
// guarantee for in-flight requests: a ticket signed under epoch N validates
// after the keyring rolls to epoch N+1, as long as N is still within the
// live window. Without this, every key rotation would invalidate every
// challenge currently in flight.
//
// matchesChallenge uses time.Since on the wall clock (not the keyring's
// overridable now), so we anchor t0 at the real current time and only
// override the keyring's clock — small enough offsets stay inside the
// ticketAgeBackstop freshness check.
func TestRotation_TicketSurvives_WithinLiveWindow(t *testing.T) {
	t0 := time.Now()
	keys := newTestKeyRing(t, testSecret, time.Minute, t0)

	c := &ChallengeRuntime{keys: keys}
	tsStr := strconvI64(t0.UnixNano())
	ticket := c.computeTicket(tsStr)
	salt := mustGeneratePowPrefix(t)
	mac := c.computePowMAC(salt, ticket, tsStr)

	// Roll the keyring clock forward one rotation interval — the ticket's
	// epoch is now "previous" but still in the live window.
	keys.now = func() time.Time { return t0.Add(70 * time.Second) }

	assert.True(t, c.matchesChallenge(ticket, tsStr, salt, mac),
		"ticket from previous epoch must still validate within the live window")
}

// TestRotation_TicketRejected_OutOfWindow proves the negative side of the
// previous test: once the keyring's view of time has advanced enough to
// evict the ticket's epoch, validation fails. Anchored at real-time t0 so
// matchesChallenge's own freshness check (time.Since) doesn't conflate with
// the keyring's eviction logic.
func TestRotation_TicketRejected_OutOfWindow(t *testing.T) {
	t0 := time.Now()
	keys := newTestKeyRing(t, testSecret, time.Minute, t0)

	c := &ChallengeRuntime{keys: keys}
	tsStr := strconvI64(t0.UnixNano())
	ticket := c.computeTicket(tsStr)
	salt := mustGeneratePowPrefix(t)
	mac := c.computePowMAC(salt, ticket, tsStr)

	// Jump the keyring's clock past the live window (maxLive=3 + skew=1 =
	// any epoch >4 minutes ahead in the keyring's view evicts the original).
	keys.now = func() time.Time { return t0.Add(5 * time.Minute) }

	assert.False(t, c.matchesChallenge(ticket, tsStr, salt, mac),
		"ticket from an evicted epoch must not validate")
}

// TestEndToEnd_ValidateChallengeResponse walks the full validation path
// (matches challenge, opens cookie). Regression guard for keyring +
// cookie-v0 wired together.
func TestEndToEnd_ValidateChallengeResponse(t *testing.T) {
	keys := testKeyRing()
	c := &ChallengeRuntime{keys: keys, powDifficulty: 8, cookieTTL: time.Hour}

	ticket, ts := freshTicket()
	body := buildValidBody(t, c.powDifficulty, ticket, ts)

	req, err := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	ck, _, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, ck)

	// Round-trip the cookie through the public ValidCookie API to confirm
	// the full Seal → parse Set-Cookie → Open path is correct.
	parsed, err := http.ParseSetCookie(ck.String())
	require.NoError(t, err)

	got, err := c.ValidCookie(parsed, "test-agent")
	require.NoError(t, err)
	assert.Equal(t, 8, got.PowDifficulty)
}

// TestCookieV0_BrowserTTLMatchesServerTTL guards the gotcha mentioned in
// the v0 design discussion: if the browser drops the cookie before the
// server stops accepting it (or vice versa), users get unexpected
// re-challenges. The Set-Cookie Max-Age MUST match the server-side
// cookieTTL.
func TestCookieV0_BrowserTTLMatchesServerTTL(t *testing.T) {
	keys := testKeyRing()
	c := &ChallengeRuntime{keys: keys, powDifficulty: 8, cookieTTL: 90 * time.Minute}

	ticket, ts := freshTicket()
	body := buildValidBody(t, c.powDifficulty, ticket, ts)

	req, err := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	ck, _, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)

	parsed, err := http.ParseSetCookie(ck.String())
	require.NoError(t, err)

	// MaxAge is a count of seconds; compare to our cookieTTL.
	// The cookie helper computes MaxAge as
	//   int(time.Until(Expires).Seconds())
	// where Expires was set from time.Now()+TTL on a slightly earlier
	// time.Now() reading. Sub-second elapsed time between the two reads
	// can shave a full second off after truncation, so we allow ±2s.
	expected := int((90 * time.Minute).Seconds())
	assert.InDelta(t, expected, parsed.MaxAge, 2,
		"browser-side Max-Age (%d) should be within 2s of server-side cookieTTL (%d)",
		parsed.MaxAge, expected)
}

func strconvI64(n int64) string {
	return strconv.FormatInt(n, 10)
}

// TestCookieV0_AllowlistRoundTrip seals an allowlist cookie (Allowlisted bit
// + reason) and confirms the open path returns both fields.
func TestCookieV0_AllowlistRoundTrip(t *testing.T) {
	keys := testKeyRing()
	notAfter := time.Now().Add(time.Hour).Unix()
	reason := "Googlebot/2.1 (compatible)"

	encoded, err := sealCookieV0(&pb.ChallengeCookie{}, keys.MasterCookieKey(), notAfter, cookieFlagAllowlisted, reason, []byte("ua"))
	require.NoError(t, err)

	got, err := openCookie(encoded, keys.MasterCookieKey(), []byte("ua"))
	require.NoError(t, err)
	assert.True(t, got.Allowlisted, "allowlist flag should round-trip true")
	assert.Equal(t, reason, got.AllowlistReason, "reason should round-trip verbatim")
}

// TestCookieV0_AllowlistFlagDefaultsFalse confirms a regular (non-allowlist)
// cookie reports Allowlisted=false and empty reason after open.
func TestCookieV0_AllowlistFlagDefaultsFalse(t *testing.T) {
	keys := testKeyRing()
	notAfter := time.Now().Add(time.Hour).Unix()

	encoded, err := sealCookieV0(&pb.ChallengeCookie{PowDifficulty: 12}, keys.MasterCookieKey(), notAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	got, err := openCookie(encoded, keys.MasterCookieKey(), []byte("ua"))
	require.NoError(t, err)
	assert.False(t, got.Allowlisted, "default flag must be false")
	assert.Empty(t, got.AllowlistReason)
}

// TestCookieV0_AllowlistReasonTooLong asserts the seal path rejects reasons
// larger than MaxAllowlistReasonLen with the typed error.
func TestCookieV0_AllowlistReasonTooLong(t *testing.T) {
	keys := testKeyRing()
	notAfter := time.Now().Add(time.Hour).Unix()
	oversize := bytes.Repeat([]byte("x"), MaxAllowlistReasonLen+1)

	_, err := sealCookieV0(&pb.ChallengeCookie{}, keys.MasterCookieKey(), notAfter, cookieFlagAllowlisted, string(oversize), []byte("ua"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAllowlistReasonSize)
}

// TestCookieV0_TamperedFlagsRejected confirms the flags byte is INSIDE the
// AEAD envelope: any modification invalidates the GCM tag.
func TestCookieV0_TamperedFlagsRejected(t *testing.T) {
	keys := testKeyRing()
	notAfter := time.Now().Add(time.Hour).Unix()

	encoded, err := sealCookieV0(&pb.ChallengeCookie{}, keys.MasterCookieKey(), notAfter, 0, "", []byte("ua"))
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Wire layout: version(1) || nonce(12) || ciphertext(...). The 9th
	// byte of ciphertext (offset 1+12+8 = 21) covers the flags_byte of
	// the plaintext. Flipping any bit there should fail the AEAD tag.
	tampered := append([]byte(nil), raw...)
	tampered[1+12+8] ^= 0x01
	tamperedEncoded := base64.RawURLEncoding.EncodeToString(tampered)

	_, err = openCookie(tamperedEncoded, keys.MasterCookieKey(), []byte("ua"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCookieSignature)
}
