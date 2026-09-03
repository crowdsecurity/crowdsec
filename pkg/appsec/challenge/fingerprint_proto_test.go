package challenge

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyboardSignal(t *testing.T) {
	t.Run("parsed from the bundle payload", func(t *testing.T) {
		fp := mustUnmarshal(t, `{"signals": {"device": {"keyboard": {
			"layout": "Backquote,` + "`" + ` Backslash,\\ BracketLeft,[",
			"layoutSize": 3
		}}}}`)

		assert.Equal(t, "Backquote,` Backslash,\\ BracketLeft,[", fp.Signals.Device.Keyboard.Layout)
		assert.Equal(t, FlexInt(3), fp.Signals.Device.Keyboard.LayoutSize)
	})

	// Browsers without navigator.keyboard (and collection errors) report "NA"
	// for both fields.
	t.Run("unsupported browser", func(t *testing.T) {
		fp := mustUnmarshal(t, `{"signals": {"device": {"keyboard": {"layout": "NA", "layoutSize": "NA"}}}}`)

		assert.Equal(t, "NA", fp.Signals.Device.Keyboard.Layout)
		assert.Equal(t, FlexInt(0), fp.Signals.Device.Keyboard.LayoutSize)
	})

	t.Run("survives the cookie proto round-trip", func(t *testing.T) {
		fp := mustUnmarshal(t, `{"signals": {"device": {"keyboard": {"layout": "KeyQ,a KeyW,z", "layoutSize": 2}}}}`)

		got := fingerprintDataFromProto(fp.ToProto())

		assert.Equal(t, fp.Signals.Device.Keyboard, got.Signals.Device.Keyboard)
	})
}

func TestAISignal(t *testing.T) {
	// availability() returns an enum string, not a bool — the library's own
	// TS type says boolean, the implementation and its tests say string.
	t.Run("availability enum", func(t *testing.T) {
		fp := mustUnmarshal(t, `{"signals": {"browser": {"ai": {
			"summarizerAvailability": "downloadable",
			"summarizerLanguageAvailability": "unavailable"
		}}}}`)

		assert.Equal(t, "downloadable", fp.Signals.Browser.AI.SummarizerAvailability)
		assert.Equal(t, "unavailable", fp.Signals.Browser.AI.SummarizerLanguageAvailability)

		got := fingerprintDataFromProto(fp.ToProto())
		assert.Equal(t, fp.Signals.Browser.AI, got.Signals.Browser.AI)
	})

	t.Run("unsupported browser", func(t *testing.T) {
		fp := mustUnmarshal(t, `{"signals": {"browser": {"ai": {"summarizerAvailability": "NA", "summarizerLanguageAvailability": "NA"}}}}`)

		assert.Equal(t, "NA", fp.Signals.Browser.AI.SummarizerAvailability)
		assert.Equal(t, "NA", fp.Signals.Browser.AI.SummarizerLanguageAvailability)
	})
}

func TestSumPreciseFeature(t *testing.T) {
	fp := mustUnmarshal(t, `{"signals": {"browser": {"features": {"otpCredential": true, "sumPrecise": true}}}}`)

	assert.True(t, fp.Signals.Browser.Features.SumPrecise.Bool())
	assert.True(t, fingerprintDataFromProto(fp.ToProto()).Signals.Browser.Features.SumPrecise.Bool())
}

func TestKeyboardSignalMissing(t *testing.T) {
	fp := &FingerprintData{}
	require.NoError(t, json.Unmarshal([]byte(`{"signals": {"device": {"cpuCount": 4}}}`), fp))

	assert.Equal(t, fingerprintDeviceKeyboard{}, fp.Signals.Device.Keyboard)
	assert.Equal(t, fingerprintDeviceKeyboard{}, fingerprintDataFromProto(fp.ToProto()).Signals.Device.Keyboard)
}
