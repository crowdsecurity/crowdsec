package appsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseChallengeCookieTTLArg covers the GrantChallengeCookie optional TTL
// argument parsing: no args / empty string yield a nil override (use runtime
// default), a parseable duration yields a positive pointer, and malformed /
// non-positive / multi-arg inputs surface as errors so hook authors see a
// precise diagnostic instead of silent fallback.
func TestParseChallengeCookieTTLArg(t *testing.T) {
	t.Run("no args → nil override", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("empty string → nil override", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg([]string{""})
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("valid duration", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg([]string{"1h30m"})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, 90*time.Minute, *got)
	})

	t.Run("malformed duration", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"forever"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid GrantChallengeCookie TTL")
	})

	t.Run("non-positive duration", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"-5m"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("multiple TTL args rejected", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"1h", "2h"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most one TTL argument")
	})
}
