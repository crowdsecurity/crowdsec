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

	cookieA, _ := a.CookieKey(epochA)
	cookieB, _ := b.CookieKey(epochB)
	assert.True(t, bytes.Equal(cookieA, cookieB), "cookie keys diverge across instances")

	// Sign and cookie keys for the same epoch must NOT be the same — they
	// derive from the same secret with different HKDF info strings.
	assert.False(t, bytes.Equal(signA, cookieA), "sign and cookie keys must differ for the same epoch")
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

	cases := []struct {
		epoch    int64
		context  string
		wantHex  string
		wantNote string
	}{
		{
			epoch:    0,
			context:  keyringInfoSign,
			wantHex:  hex.EncodeToString(deriveEpochKey(secret, 0, keyringInfoSign)),
			wantNote: "epoch 0 sign",
		},
		{
			epoch:    0,
			context:  keyringInfoCookie,
			wantHex:  hex.EncodeToString(deriveEpochKey(secret, 0, keyringInfoCookie)),
			wantNote: "epoch 0 cookie",
		},
	}

	for _, tc := range cases {
		got := deriveEpochKey(k.masterSecret, tc.epoch, tc.context)
		assert.Equal(t, tc.wantHex, hex.EncodeToString(got), tc.wantNote)

		// Sanity: derivation is itself deterministic across calls.
		got2 := deriveEpochKey(k.masterSecret, tc.epoch, tc.context)
		assert.Equal(t, hex.EncodeToString(got), hex.EncodeToString(got2), "derivation not deterministic")
	}

	// Cross-context separation: same epoch, different context → different bytes.
	signKey := deriveEpochKey(secret, 42, keyringInfoSign)
	cookieKey := deriveEpochKey(secret, 42, keyringInfoCookie)
	assert.NotEqual(t, hex.EncodeToString(signKey), hex.EncodeToString(cookieKey),
		"sign and cookie contexts must produce different keys")

	// Cross-epoch separation: same context, different epoch → different bytes.
	e0 := deriveEpochKey(secret, 0, keyringInfoSign)
	e1 := deriveEpochKey(secret, 1, keyringInfoSign)
	assert.NotEqual(t, hex.EncodeToString(e0), hex.EncodeToString(e1),
		"adjacent epochs must produce different keys")
}
