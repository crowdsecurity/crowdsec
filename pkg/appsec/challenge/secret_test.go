package challenge

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfiguredSecret_Hex(t *testing.T) {
	// 32 raw bytes = 64 hex chars
	hex := strings.Repeat("ab", 32)
	got, err := ParseConfiguredSecret(hex)
	require.NoError(t, err)
	assert.Len(t, got, 32)
}

func TestParseConfiguredSecret_HexTooShort(t *testing.T) {
	// 31 raw bytes = 62 hex chars → must be rejected
	hex := strings.Repeat("ab", 31)
	_, err := ParseConfiguredSecret(hex)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minimum is 32")
}

func TestParseConfiguredSecret_Passphrase(t *testing.T) {
	// "long enough passphrase, definitely > 32 bytes" — 47 bytes
	pw := "long enough passphrase, definitely > 32 bytes"
	got, err := ParseConfiguredSecret(pw)
	require.NoError(t, err)
	assert.Equal(t, []byte(pw), got)
}

func TestParseConfiguredSecret_PassphraseTooShort(t *testing.T) {
	_, err := ParseConfiguredSecret("short")
	require.Error(t, err)
}

func TestParseConfiguredSecret_Empty(t *testing.T) {
	_, err := ParseConfiguredSecret("")
	require.Error(t, err)
}

func TestGenerateRandomSecret(t *testing.T) {
	a, err := generateRandomSecret()
	require.NoError(t, err)
	b, err := generateRandomSecret()
	require.NoError(t, err)

	assert.Len(t, a, 32)
	assert.Len(t, b, 32)
	assert.NotEqual(t, a, b, "successive calls must yield different secrets")
}

func TestNewChallengeRuntime_RejectsShortSecret(t *testing.T) {
	// Bypassing ParseConfiguredSecret to feed the runtime a too-short secret
	// directly via the option — the runtime itself must defend against this.
	short := []byte("too-short")
	_, err := NewChallengeRuntime(t.Context(), WithMasterSecret(short))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
}
