package challenge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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

// cookieHeadroomFloor is the slack a realistic envelope must keep for the
// custom map and for growth, so that eating the margin with a new fpscanner
// signal is a reviewed decision rather than something users discover as
// challenges failing on browsers with long user agents.
const cookieHeadroomFloor = 1024

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

	assert.LessOrEqual(t, size+cookieHeadroomFloor, ceiling,
		"a realistic fingerprint no longer leaves %d bytes of slack; trim a signal",
		cookieHeadroomFloor)
}
