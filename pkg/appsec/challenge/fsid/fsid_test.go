package fsid

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sample is a hand-built FSID exercising every section, including a timezone
// that contains the '_' section separator (America/New_York -> America-New_York).
const sample = "FS1_000000000000000100000_00000h1a2b_1920x1080c08m08b10011h-3f2a1c_" +
	"f11000000000000000000000000000e00000000p1100h4b2c1d_0h1f3e5a_1h2a4b6c_" +
	"en3tAmerica-New_York_h7f2a_0000h9a8b7c"

func TestParse(t *testing.T) {
	f, err := Parse(sample)
	require.NoError(t, err)
	require.Empty(t, f.Warnings)

	assert.Equal(t, "FS1", f.Version)
	assert.True(t, f.Detections["hasUTCTimezone"])
	assert.False(t, f.Detections["hasWebdriver"])
	assert.Equal(t, 1920, f.Width)
	assert.Equal(t, 1080, f.Height)
	assert.Equal(t, 8, f.CPUCount)
	assert.Equal(t, 8, f.Memory)
	assert.True(t, f.Device["screenResolution.hasMultipleDisplays"])
	assert.False(t, f.Device["mediaQueries.prefersReducedMotion"])
	assert.True(t, f.Features["chrome"])
	assert.True(t, f.Features["brave"])
	assert.False(t, f.Features["applePaySupport"])
	assert.True(t, f.Plugins["plugins.isValidPluginArray"])
	assert.False(t, f.ModifiedCanvas)
	assert.True(t, f.HasMediaSource)
	assert.Equal(t, "en", f.Language)
	assert.Equal(t, 3, f.LangCount)
	assert.Equal(t, "America-New_York", f.Timezone)
	assert.Equal(t, "-3f2a1c", f.Hashes["device"])
	assert.Equal(t, "9a8b7c", f.Hashes["contexts"])
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		expectedErr string
	}{
		{name: "empty", raw: "  ", expectedErr: "empty fsid"},
		{name: "too few sections", raw: "FS1_0_0", expectedErr: "expected at least 9 '_'-separated sections, got 3"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.raw)
			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}

// A section this build cannot decode is a warning, not a failure: the rest of
// the FSID stays readable.
func TestParseWarnings(t *testing.T) {
	raw := strings.Replace(sample, "FS1_", "FS2_", 1)
	raw = strings.Replace(raw, "0h1f3e5a", "garbage", 1)

	f, err := Parse(raw)
	require.NoError(t, err)

	assert.Contains(t, f.Warnings, `unknown version "FS2", decoding as FS1`)
	assert.Contains(t, f.Warnings, `cannot parse graphics section "garbage"`)
	assert.Equal(t, 1920, f.Width)
}

func TestFingerprint(t *testing.T) {
	f, err := Parse(sample)
	require.NoError(t, err)

	fp := f.Fingerprint()
	assert.Equal(t, sample, fp["fsid"])
	assert.Equal(t, true, fp["fastBotDetection"])

	details := fp["fastBotDetectionDetails"].(map[string]any)
	assert.Equal(t, map[string]any{"detected": true, "severity": "medium"}, details["hasUTCTimezone"])
	assert.Equal(t, map[string]any{"detected": false, "severity": "high"}, details["hasWebdriver"])

	signals := fp["signals"].(map[string]any)
	device := signals["device"].(map[string]any)
	assert.Equal(t, 8, device["cpuCount"])
	assert.Equal(t, 1920, device["screenResolution"].(map[string]any)["width"])

	browser := signals["browser"].(map[string]any)
	assert.Equal(t, "11000000000000000000000000000", browser["features"].(map[string]any)["bitmask"])
	assert.Equal(t, []string{}, browser["extensions"].(map[string]any)["extensions"])
}

func TestWriteHuman(t *testing.T) {
	f, err := Parse(sample)
	require.NoError(t, err)

	out := &strings.Builder{}
	f.WriteHuman(out)

	assert.Contains(t, out.String(), "screen       1920x1080")
	assert.Contains(t, out.String(), "hasUTCTimezone")
	assert.Contains(t, out.String(), "timezone     America-New_York")
}
