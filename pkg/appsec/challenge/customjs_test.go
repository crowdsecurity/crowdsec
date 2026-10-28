package challenge

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// customSentinel must match the constant in challenge.js (CSEC_CUSTOM_NAME) and
// in obfuscate.js (reservedStrings). Hardcoded so a rename that misses one of
// them fails here rather than silently in the browser, where the hub script and
// the challenge bundle would no longer meet.
const customSentinel = "__CSEC_CUSTOM_DETECT_v1__"

func TestCustomJS_SentinelSurvivesObfuscation(t *testing.T) {
	rt := &ChallengeRuntime{}
	require.NoError(t, rt.seedCacheFromInitialBundle())

	assert.Contains(t, rt.getChallengeCode(), customSentinel,
		"was %s dropped from reservedStrings in obfuscate.js?", customSentinel)
}

func TestCustomJS_ScriptTag(t *testing.T) {
	rt := newChallengeRuntimeForSplitTest(t, testKeyRing())

	// Unreferenced with no script loaded, so a challenge page doesn't request a
	// file that isn't there.
	html, err := rt.GetChallengePage(t.Context(), "test-agent", 8)
	require.NoError(t, err)
	require.NotContains(t, html, ChallengeCustomJSPath)

	rt.setCustomJS("globalThis.__CSEC_CUSTOM_DETECT_v1__ = [];")

	html, err = rt.GetChallengePage(t.Context(), "test-agent", 8)
	require.NoError(t, err)
	assert.Contains(t, html, ChallengeCustomJSPath)

	// Served from its own cacheable path, not inlined.
	assert.NotContains(t, html, rt.customJS)

	// Registration has to precede the module that invokes the hooks.
	assert.Less(t, strings.Index(html, ChallengeCustomJSPath), strings.Index(html, `<script type="module">`))
}

// The full chain a hub-shipped script depends on: client-side obfuscation,
// signature check, JSON decode, proto conversion, sealed cookie.
func TestCustomDetectSurvivesFullSubmission(t *testing.T) {
	c := &ChallengeRuntime{keys: testKeyRing(), powDifficulty: 8, cookieTTL: time.Hour, spent: newSpentSet(spentSetDefaultMaxEntries)}

	submitted := FingerprintData{
		FSID: "FS1_custom",
		Custom: map[string]CustomValue{
			"audioCtxNoise": {Kind: CustomKindBool, Bool: true},
			"clearedByHook": {Kind: CustomKindBool, Bool: false},
			"audioHash":     {Kind: CustomKindString, Str: "a91f2c3d"},
			"collectMs":     {Kind: CustomKindNumber, Number: 512},
			"fonts":         {Kind: CustomKindStrings, Strings: []string{"Arial", "Helvetica"}},
		},
	}

	r, ts := freshChallenge(t)
	body := buildValidBodyWithFingerprint(t, c.powDifficulty, r, ts, submitted)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/submit", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	ck, decoded, _, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, ck)

	// What on_challenge_submit sees.
	assert.Equal(t, submitted.Custom, decoded.Custom)

	// And what on_challenge sees on every later request.
	parsed, err := http.ParseSetCookie(ck.String())
	require.NoError(t, err)

	cd, err := c.ValidCookie(parsed, "test-agent")
	require.NoError(t, err)
	assert.Equal(t, submitted.Custom, cd.Fingerprint.Custom)

	// A hook that cleared a detection reports false, distinct from unset.
	assert.True(t, cd.Fingerprint.HasCustom("clearedByHook"))
	assert.False(t, cd.Fingerprint.Custom["clearedByHook"].Bool)
	assert.False(t, cd.Fingerprint.HasCustom("neverSet"))
}

// A script that reports more than the cookie can hold must not cost the visitor
// their submission: the map is dropped, the cookie is still minted, and the
// rules on this request still see everything that was reported.
func TestOversizedCustomStillYieldsACookie(t *testing.T) {
	c := &ChallengeRuntime{keys: testKeyRing(), powDifficulty: 8, cookieTTL: time.Hour, spent: newSpentSet(spentSetDefaultMaxEntries)}

	custom := oversizedCustom()
	submitted := FingerprintData{FSID: "FS1_fat", Custom: custom}

	r, ts := freshChallenge(t)
	body := buildValidBodyWithFingerprint(t, c.powDifficulty, r, ts, submitted)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/submit", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	ck, decoded, _, err := c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, ck)

	assert.Equal(t, custom, decoded.Custom)

	parsed, err := http.ParseSetCookie(ck.String())
	require.NoError(t, err)

	cd, err := c.ValidCookie(parsed, "test-agent")
	require.NoError(t, err)

	// Shed on the way into the cookie, so later requests see none of it.
	assert.Empty(t, cd.Fingerprint.Custom)
	assert.Equal(t, "FS1_fat", cd.Fingerprint.FSID)
}

// oversizedCustom reports far more than the ~1kB the fingerprint leaves in the
// cookie, so sealing always overflows.
func oversizedCustom() map[string]CustomValue {
	custom := make(map[string]CustomValue, 40)

	for i := range 40 {
		custom[fmt.Sprintf("detector%02d", i)] = CustomValue{
			Kind: CustomKindString,
			Str:  strings.Repeat("x", 200),
		}
	}

	return custom
}

// Overflow follows from what the detectors report, not from the visitor, so an
// operator has to see it — but not once per submission.
func TestCustomOverflowWarnsOnce(t *testing.T) {
	capture, hook := logtest.NewNullLogger()
	capture.SetLevel(log.DebugLevel)

	c := &ChallengeRuntime{
		keys:          testKeyRing(),
		powDifficulty: 8,
		cookieTTL:     time.Hour,
		spent:         newSpentSet(spentSetDefaultMaxEntries),
		logger:        log.NewEntry(capture),
	}

	submitted := FingerprintData{FSID: "FS1_fat", Custom: oversizedCustom()}

	for range 3 {
		// A fresh nonce per iteration: the first one is burnt on use.
		r, ts := freshChallenge(t)
		body := buildValidBodyWithFingerprint(t, c.powDifficulty, r, ts, submitted)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/submit", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("User-Agent", "test-agent")

		ck, _, _, err := c.ValidateChallengeResponse(req, []byte(body))
		require.NoError(t, err)
		require.NotNil(t, ck)
	}

	var warns, debugs int

	for _, e := range hook.AllEntries() {
		if !strings.Contains(e.Message, "do not fit in the cookie") {
			continue
		}

		switch e.Level {
		case log.WarnLevel:
			warns++
		case log.DebugLevel:
			debugs++
		}
	}

	require.Equal(t, 1, warns)
	require.Equal(t, 2, debugs)
}
