package challenge

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCookieV1_RoundTrip seals a cookie under epoch N's key and opens it
// using the keyring's resolver — the basic positive case.
func TestCookieV1_RoundTrip(t *testing.T) {
	keys := testKeyRing()
	epoch, key := keys.CurrentCookie()

	envelope := &pb.ChallengeCookie{PowDifficulty: 12}
	aad := []byte("test-ua")

	encoded, err := sealCookieV1(envelope, key, epoch, aad)
	require.NoError(t, err)

	got, err := openCookie(encoded, keys.CookieKey, aad)
	require.NoError(t, err)
	assert.Equal(t, int32(12), got.GetPowDifficulty())
}

// TestCookieV1_EpochTagBoundToAAD asserts that the AEAD AAD includes the
// epoch — flipping the epoch tag in the wire format must invalidate the
// AEAD signature, not just shift to a different decryption key.
func TestCookieV1_EpochTagBoundToAAD(t *testing.T) {
	keys := testKeyRing()
	epoch, key := keys.CurrentCookie()

	encoded, err := sealCookieV1(&pb.ChallengeCookie{PowDifficulty: 7}, key, epoch, []byte("ua"))
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Flip the epoch byte at offset 8 (last byte of the be8-encoded epoch).
	tampered := append([]byte(nil), raw...)
	tampered[8] ^= 0x01
	tamperedEncoded := base64.RawURLEncoding.EncodeToString(tampered)

	_, err = openCookie(tamperedEncoded, keys.CookieKey, []byte("ua"))
	require.Error(t, err, "tampering with the epoch byte must invalidate the cookie")
}

// TestCookieV1_OutOfWindowRejected ensures a cookie sealed under an epoch
// that has fallen out of the live window is rejected with the typed error.
func TestCookieV1_OutOfWindowRejected(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	keys := newTestKeyRing(t, testSecret, time.Minute, t0)

	epoch, key := keys.CurrentCookie()
	encoded, err := sealCookieV1(&pb.ChallengeCookie{PowDifficulty: 9}, key, epoch, []byte("ua"))
	require.NoError(t, err)

	// Fast-forward beyond the live window (maxLive=3 + skew=1 means
	// jumping past current+4 leaves epoch out of window).
	keys.now = func() time.Time { return t0.Add(10 * time.Minute) }

	_, err = openCookie(encoded, keys.CookieKey, []byte("ua"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCookieEpoch, "out-of-window epoch should produce ErrCookieEpoch")
}

// TestCookieV1_UAMismatchRejected confirms the existing User-Agent AAD binding
// still holds under the v1 format.
func TestCookieV1_UAMismatchRejected(t *testing.T) {
	keys := testKeyRing()
	epoch, key := keys.CurrentCookie()

	encoded, err := sealCookieV1(&pb.ChallengeCookie{}, key, epoch, []byte("ua-A"))
	require.NoError(t, err)

	_, err = openCookie(encoded, keys.CookieKey, []byte("ua-B"))
	assert.ErrorIs(t, err, ErrCookieSignature)
}

// TestCookie_UnknownVersionRejected makes the version-byte dispatch
// explicit: a cookie with an unknown leading byte is rejected with the
// dedicated ErrCookieVersion sentinel rather than being attempted as
// some other format. This is the extension point for any future cookie
// schema (e.g. a v2 that decouples cookie key from epoch).
func TestCookie_UnknownVersionRejected(t *testing.T) {
	keys := testKeyRing()

	// Forge: version byte 0xFE followed by random-looking junk.
	raw := append([]byte{0xFE}, []byte("0123456789abcdefghijklmnop")...)
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	_, err := openCookie(encoded, keys.CookieKey, []byte("ua"))
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
// challengeJSRefreshInterval freshness check.
func TestRotation_TicketSurvives_WithinLiveWindow(t *testing.T) {
	t0 := time.Now()
	keys := newTestKeyRing(t, testSecret, time.Minute, t0)

	c := &ChallengeRuntime{keys: keys}
	tsStr := strconvI64(t0.UnixNano())
	ticket := c.computeTicket(tsStr)
	salt := generatePowPrefix()
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
	salt := generatePowPrefix()
	mac := c.computePowMAC(salt, ticket, tsStr)

	// Jump the keyring's clock past the live window (maxLive=3 + skew=1 =
	// any epoch >4 minutes ahead in the keyring's view evicts the original).
	keys.now = func() time.Time { return t0.Add(5 * time.Minute) }

	assert.False(t, c.matchesChallenge(ticket, tsStr, salt, mac),
		"ticket from an evicted epoch must not validate")
}

// TestCookie_AuthenticatedUserSurvivesRotation answers the operator
// question "does rotating the secret kick existing authenticated users
// back to a challenge?". The answer is no — cookies sealed under epoch N
// continue to validate after rotations to N+1, N+2, ... up to the live
// window's edge. Beyond that, users are re-challenged.
//
// This test exercises the round trip explicitly: seal a cookie, advance
// the keyring by one rotation, open the cookie — must succeed.
func TestCookie_AuthenticatedUserSurvivesRotation(t *testing.T) {
	t0 := time.Now()
	keys := newTestKeyRing(t, testSecret, time.Minute, t0)

	// Seal a cookie under the current epoch.
	envelope := &pb.ChallengeCookie{PowDifficulty: 12}
	epoch, key := keys.CurrentCookie()
	encoded, err := sealCookieV1(envelope, key, epoch, []byte("ua"))
	require.NoError(t, err)

	// Advance the keyring by one rotation interval. The cookie's epoch
	// is now "previous" but still inside the live window.
	keys.now = func() time.Time { return t0.Add(70 * time.Second) }

	got, err := openCookie(encoded, keys.CookieKey, []byte("ua"))
	require.NoError(t, err, "cookie should validate one rotation after issuance")
	assert.Equal(t, int32(12), got.GetPowDifficulty())

	// One more rotation: maxLive=3 means [current-2 ... current+skew]
	// includes the original epoch when current = E0 + 2. Cookie still
	// validates at the edge of the live window.
	keys.now = func() time.Time { return t0.Add(130 * time.Second) }
	_, err = openCookie(encoded, keys.CookieKey, []byte("ua"))
	require.NoError(t, err, "cookie should validate at the edge of the live window")

	// One rotation more (current = E0 + 3): original epoch now evicted.
	keys.now = func() time.Time { return t0.Add(190 * time.Second) }
	_, err = openCookie(encoded, keys.CookieKey, []byte("ua"))
	require.Error(t, err, "cookie must be rejected once its epoch is out of window")
	assert.ErrorIs(t, err, ErrCookieEpoch)
}

// TestEndToEnd_ValidateChallengeResponse_AcrossRotation walks the full
// validation path (matches challenge, opens cookie) for a submission whose
// ticket was issued under a previous-but-still-live epoch. Regression guard
// for keyring + cookie-v1 wired together.
func TestEndToEnd_ValidateChallengeResponse_AcrossRotation(t *testing.T) {
	keys := testKeyRing()
	c := &ChallengeRuntime{keys: keys, powDifficulty: 8}

	ticket, ts := freshTicket()
	body := buildValidBody(c.powDifficulty, ticket, ts)

	req, err := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	ck, _, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, ck)

	// The cookie must now decode through the cookie-v1 path. Round-trip it
	// through ValidCookie to make sure the integration is correct.
	parsed, err := http.ParseSetCookie(ck.String())
	require.NoError(t, err)

	got, err := c.ValidCookie(parsed, "test-agent")
	require.NoError(t, err)
	assert.Equal(t, 8, got.PowDifficulty)
}

func strconvI64(n int64) string {
	// avoid pulling strconv into another helper file
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf bytes.Buffer
	for n > 0 {
		buf.WriteByte(digits[n%10])
		n /= 10
	}
	out := buf.Bytes()
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if negative {
		return "-" + string(out)
	}
	return string(out)
}
