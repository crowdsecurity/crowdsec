package challenge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
)

func TestCustomProtoRoundTrip(t *testing.T) {
	in := map[string]CustomValue{
		"aBool":       {Kind: CustomKindBool, Bool: true},
		"aFalseBool":  {Kind: CustomKindBool, Bool: false},
		"aString":     {Kind: CustomKindString, Str: "a91f"},
		"aNumber":     {Kind: CustomKindNumber, Number: 512.5},
		"someStrings": {Kind: CustomKindStrings, Strings: []string{"Arial", "Helvetica"}},
		"someFloats":  {Kind: CustomKindFloats, Floats: []float64{12.5, 30}},
	}

	fp := FingerprintData{Custom: in}

	got := fingerprintDataFromProto(fp.ToProto())

	assert.Equal(t, in, got.Custom)

	// "present and false" must survive distinctly from "absent".
	assert.True(t, got.HasCustom("aFalseBool"))
	assert.False(t, got.Custom["aFalseBool"].Bool)
	assert.False(t, got.HasCustom("neverSet"))
}

func TestCustomProtoEmptyStaysNil(t *testing.T) {
	assert.Nil(t, (&FingerprintData{}).ToProto().GetCustom())
	assert.Nil(t, customToProto(map[string]CustomValue{"x": {}}))
	assert.Nil(t, customFromProto(nil))
	// What a truncated or older writer leaves behind.
	assert.Nil(t, customFromProto(map[string]*pb.CustomValue{"x": {}}))
}

// The custom map is the one part of the envelope a client can inflate. Shedding
// it keeps the visitor able to obtain a cookie at all.
func TestSealShedsOversizedCustom(t *testing.T) {
	custom := make(map[string]CustomValue, MaxCustomKeys)
	for i := range MaxCustomKeys {
		custom[string(rune('a'+i/26))+string(rune('a'+i%26))] = CustomValue{
			Kind: CustomKindString,
			Str:  strings.Repeat("x", MaxCustomStringLen),
		}
	}

	fp := FingerprintData{FSID: "FS1_x", Custom: custom}
	envelope := &pb.ChallengeCookie{Fingerprint: fp.ToProto(), PowDifficulty: PowDifficultyMedium}

	require.Greater(t, proto.Size(envelope), MaxCookieLen, "fixture should start over budget")

	key := make([]byte, 32)

	encoded, err := sealCookieV0(envelope, key, time.Now().Add(time.Hour).Unix(), 0, "", []byte("ua"), MaxCookieLen)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(encoded), MaxCookieLen)

	opened, err := openCookie(encoded, key, []byte("ua"), MaxCookieLen)
	require.NoError(t, err)

	got := fingerprintDataFromProto(opened.Envelope.GetFingerprint())

	// Trimmed, not emptied, and the rest of the fingerprint is intact.
	assert.NotEmpty(t, got.Custom)
	assert.Less(t, len(got.Custom), MaxCustomKeys)
	assert.Equal(t, "FS1_x", got.FSID)
}

// Which entries survive must not depend on map iteration order, or a single
// submission would seal to a different cookie on every request.
func TestSealShedsCustomDeterministically(t *testing.T) {
	build := func() *pb.ChallengeCookie {
		custom := make(map[string]CustomValue, MaxCustomKeys)
		for i := range MaxCustomKeys {
			custom[string(rune('a'+i/26))+string(rune('a'+i%26))] = CustomValue{
				Kind: CustomKindString,
				Str:  strings.Repeat("x", MaxCustomStringLen),
			}
		}

		fp := FingerprintData{FSID: "FS1_x", Custom: custom}

		return &pb.ChallengeCookie{Fingerprint: fp.ToProto(), PowDifficulty: PowDifficultyMedium}
	}

	first := build()
	require.Positive(t, fitCustomToBudget(first, 3000))

	want := fingerprintDataFromProto(first.GetFingerprint()).Custom
	require.NotEmpty(t, want)

	for range 20 {
		other := build()
		fitCustomToBudget(other, 3000)
		require.Equal(t, want, fingerprintDataFromProto(other.GetFingerprint()).Custom)
	}
}

// The cap has to bind even when the cookie as a whole still fits, so custom
// entries can't consume the headroom fpscanner needs to grow.
func TestCustomCappedBelowFullBudget(t *testing.T) {
	custom := make(map[string]CustomValue, MaxCustomKeys)
	for i := range MaxCustomKeys {
		custom[string(rune('a'+i/26))+string(rune('a'+i%26))] = CustomValue{
			Kind: CustomKindString,
			Str:  strings.Repeat("x", MaxCustomStringLen),
		}
	}

	fp := FingerprintData{Custom: custom}
	envelope := &pb.ChallengeCookie{Fingerprint: fp.ToProto()}

	fitCustomToBudget(envelope, 1<<20) // budget deliberately not the constraint

	withCustom := proto.Size(envelope)
	envelope.GetFingerprint().Custom = nil

	assert.LessOrEqual(t, withCustom-proto.Size(envelope), MaxCustomCookieBytes)
}

// A normal-sized map is left alone.
func TestSealKeepsReasonableCustom(t *testing.T) {
	fp := FingerprintData{
		FSID: "FS1_x",
		Custom: map[string]CustomValue{
			"audioCtxNoise": {Kind: CustomKindBool, Bool: true},
			"audioHash":     {Kind: CustomKindString, Str: "a91f2c3d"},
			"collectMs":     {Kind: CustomKindNumber, Number: 512},
		},
	}

	envelope := &pb.ChallengeCookie{Fingerprint: fp.ToProto(), PowDifficulty: PowDifficultyMedium}

	assert.Equal(t, 0, fitCustomToBudget(envelope, 3000))
	assert.Equal(t, fp.Custom, fingerprintDataFromProto(envelope.GetFingerprint()).Custom)
}

// cookieHeadroomFloor is the slack a realistic envelope must keep once custom
// entries have taken their share, so that eating the margin with a new
// fpscanner signal is a reviewed decision rather than something users discover
// as challenges failing on browsers with long user agents.
const cookieHeadroomFloor = 512

func TestRealisticFingerprintLeavesCookieHeadroom(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "realistic_fingerprint.json"))
	require.NoError(t, err)

	var fp FingerprintData
	require.NoError(t, json.Unmarshal(raw, &fp))

	// A stub fixture would make the headroom assertion meaningless.
	require.NotEmpty(t, fp.FSID)
	require.NotEmpty(t, fp.Signals.Browser.UserAgent)
	require.NotEmpty(t, fp.Signals.Device.Keyboard.Layout)

	envelope := &pb.ChallengeCookie{Fingerprint: fp.ToProto(), PowDifficulty: PowDifficultyMedium}

	// Mirrors sealCookieV0: base64 expansion, version byte, GCM nonce and tag.
	ceiling := MaxCookieLen/4*3 - 1 - 12 - 16 - cookiePlaintextFixedHeaderLen
	size := proto.Size(envelope)

	t.Logf("realistic envelope: %d bytes, ceiling %d, headroom %d", size, ceiling, ceiling-size)

	assert.LessOrEqual(t, size+MaxCustomCookieBytes+cookieHeadroomFloor, ceiling,
		"a realistic fingerprint plus a full custom map no longer leaves %d bytes of slack; "+
			"either trim a signal or revisit MaxCustomCookieBytes", cookieHeadroomFloor)
}
