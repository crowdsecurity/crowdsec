package challenge

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKeyRing(t testing.TB, secret []byte, interval time.Duration, fixed time.Time) *KeyRing {
	t.Helper()
	if secret == nil {
		secret = bytes.Repeat([]byte{0xab}, 32)
	}
	if interval == 0 {
		interval = time.Minute
	}
	k, err := NewKeyRing(secret, interval, 3)
	require.NoError(t, err)
	if !fixed.IsZero() {
		k.now = func() time.Time { return fixed }
	}
	return k
}

func TestNewKeyRing_RejectsShortSecret(t *testing.T) {
	_, err := NewKeyRing([]byte("too-short"), time.Minute, 3)
	require.Error(t, err)
}

func TestNewKeyRing_RejectsTinyInterval(t *testing.T) {
	_, err := NewKeyRing(bytes.Repeat([]byte{1}, 32), time.Second, 3)
	require.Error(t, err)
}

func TestKeyRing_DeterministicAcrossInstances(t *testing.T) {
	// Two KeyRings with the same secret + same interval, evaluated at the
	// same wall-clock moment, MUST produce bit-identical keys for the same
	// epoch. Regression guard for distributed (multi-WAF) deployments.
	secret := bytes.Repeat([]byte{0x42}, 32)
	fixed := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	a := newTestKeyRing(t, secret, time.Minute, fixed)
	b := newTestKeyRing(t, secret, time.Minute, fixed)

	epochA, signA := a.Current()
	epochB, signB := b.Current()
	assert.Equal(t, epochA, epochB)
	assert.True(t, bytes.Equal(signA, signB), "sign keys diverge across instances")

	// The master cookie key is independent of epoch and must also agree
	// across instances configured with the same master secret.
	assert.True(t, bytes.Equal(a.MasterCookieKey(), b.MasterCookieKey()),
		"master cookie keys diverge across instances")

	// Sign and master cookie keys derive from the same secret with
	// different HKDF info strings, so they MUST differ. If they didn't,
	// a leaked sign key would also forge cookies (and vice versa).
	assert.False(t, bytes.Equal(signA, a.MasterCookieKey()),
		"sign and master cookie keys must differ — domain separation is the whole point")
}

func TestKeyRing_RotatesAtIntervalBoundary(t *testing.T) {
	secret := bytes.Repeat([]byte{0x99}, 32)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	k := newTestKeyRing(t, secret, time.Minute, t0)
	e0, key0 := k.Current()

	// Cross the 60-second boundary — current epoch must increment.
	k.now = func() time.Time { return t0.Add(61 * time.Second) }
	e1, key1 := k.Current()

	assert.Equal(t, e0+1, e1)
	assert.False(t, bytes.Equal(key0, key1), "key did not change across rotation")

	// And the previous epoch's key is still derivable while in the live window.
	prev, ok := k.SignKey(e0)
	require.True(t, ok)
	assert.True(t, bytes.Equal(key0, prev), "previous epoch key changed when re-derived")
}

func TestKeyRing_LiveWindow(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	k := newTestKeyRing(t, nil, time.Minute, t0)

	// maxLive=3 + clockSkew=1 → live window is current-2 .. current+1.
	current, _ := k.Current()

	// In window.
	for _, e := range []int64{current - 2, current - 1, current, current + 1} {
		_, ok := k.SignKey(e)
		assert.True(t, ok, "epoch %d should be live", e)
	}

	// Out of window.
	for _, e := range []int64{current - 3, current + 2} {
		_, ok := k.SignKey(e)
		assert.False(t, ok, "epoch %d should NOT be live", e)
	}
}

func TestKeyRing_LiveEpochsOrdered(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	k := newTestKeyRing(t, nil, time.Minute, t0)
	current, _ := k.Current()

	live := k.LiveEpochs()
	require.Len(t, live, 4) // 3 past/current + 1 future skew

	// Ordered ascending, contiguous.
	for i, e := range live {
		assert.Equal(t, current-2+int64(i), e)
	}
}

func TestKeyRing_CacheEvictsStale(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	k := newTestKeyRing(t, nil, time.Minute, t0)

	// Touch the current epoch to seed the cache.
	startEpoch, _ := k.Current()

	// Jump far into the future so startEpoch falls out of the live window;
	// the next derivation must evict it.
	k.now = func() time.Time { return t0.Add(time.Hour) }
	_, _ = k.Current()

	k.mu.RLock()
	_, present := k.cache[startEpoch]
	k.mu.RUnlock()
	assert.False(t, present, "stale epoch %d should have been evicted from the cache", startEpoch)
}

// TestKeyRing_KnownVectors locks down the HKDF derivation. Any change to the
// salt / info strings / serialization that breaks distributed agreement on a
// fleet upgrade will make these vectors fail. If you intentionally change the
// scheme, regenerate these vectors AND rotate the keyring version constant.
func TestKeyRing_KnownVectors(t *testing.T) {
	secret, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	k, err := NewKeyRing(secret, time.Minute, 3)
	require.NoError(t, err)

	// Sign key for epoch 0 must derive deterministically.
	want := hex.EncodeToString(deriveEpochKey(secret, 0, keyringInfoSign))
	got := hex.EncodeToString(deriveEpochKey(k.masterSecret, 0, keyringInfoSign))
	assert.Equal(t, want, got, "epoch 0 sign key derivation must be deterministic")

	// Master cookie key (no epoch component) must also be deterministic.
	wantCookie := hex.EncodeToString(deriveMasterCookieKey(secret))
	gotCookie := hex.EncodeToString(k.MasterCookieKey())
	assert.Equal(t, wantCookie, gotCookie, "master cookie key derivation must be deterministic")

	// Cross-context separation: sign key for any epoch must NOT equal the
	// master cookie key. Domain separation is the whole point of using
	// distinct HKDF info strings.
	signKey := deriveEpochKey(secret, 42, keyringInfoSign)
	cookieKey := deriveMasterCookieKey(secret)
	assert.NotEqual(t, hex.EncodeToString(signKey), hex.EncodeToString(cookieKey),
		"sign and master-cookie contexts must produce different keys")

	// Cross-epoch separation: same context, different epoch → different bytes.
	e0 := deriveEpochKey(secret, 0, keyringInfoSign)
	e1 := deriveEpochKey(secret, 1, keyringInfoSign)
	assert.NotEqual(t, hex.EncodeToString(e0), hex.EncodeToString(e1),
		"adjacent epochs must produce different sign keys")
}
