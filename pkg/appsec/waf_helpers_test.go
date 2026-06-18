package appsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLegitimateBotHooksCompile guards the env maps: a hook referencing
// IsLegitimateBot/ExemptFromChallenge must compile in every phase exposing them.
func TestLegitimateBotHooksCompile(t *testing.T) {
	for _, stage := range []hookStage{hookPreEval, hookPostEval, hookOnMatch} {
		h := &Hook{
			Filter: `IsLegitimateBot(req.RemoteAddr, req.UserAgent(), req.URL.Path)`,
			Apply:  []string{`ExemptFromChallenge()`},
		}
		require.NoError(t, h.Build(t.Context(), stage, nil), "stage %v", stage)
	}
}

// TestExemptFromChallengeEscapeHatch verifies the per-request escape hatch:
// once ExemptFromChallenge was called, IsLegitimateBot returns true without
// consulting datafiles (none are loaded here) or DNS.
func TestExemptFromChallengeEscapeHatch(t *testing.T) {
	state := &AppsecRequestState{HookVars: map[string]string{}}
	env := GetPreEvalEnv(t.Context(), &AppsecRuntimeConfig{}, state, &ParsedRequest{})

	isLegit := env["IsLegitimateBot"].(func(string, string, string) bool)
	exempt := env["ExemptFromChallenge"].(func() error)

	assert.False(t, isLegit("1.2.3.4", "googlebot", "/"))

	require.NoError(t, exempt())
	assert.True(t, isLegit("1.2.3.4", "googlebot", "/"))
	assert.True(t, isLegit("garbage-ip", "", ""), "escape hatch bypasses all checks")

	// the flag is per-request state: a fresh state starts clean
	freshEnv := GetPreEvalEnv(t.Context(), &AppsecRuntimeConfig{}, &AppsecRequestState{HookVars: map[string]string{}}, &ParsedRequest{})
	assert.False(t, freshEnv["IsLegitimateBot"].(func(string, string, string) bool)("1.2.3.4", "googlebot", "/"))
}

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
