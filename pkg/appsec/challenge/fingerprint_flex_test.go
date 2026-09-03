package challenge

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A collector that throws is reported as a bare sentinel string where the
// object was expected. Decoding must drop that one signal, not the payload.
func TestFlexStructSentinel(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		assertFP func(t *testing.T, fp *FingerprintData)
	}{
		{
			name: "screenResolution",
			raw:  `{"signals": {"device": {"cpuCount": 14, "screenResolution": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintScreenResolution{}, fp.Signals.Device.ScreenResolution)
				assert.Equal(t, FlexInt(14), fp.Signals.Device.CPUCount)
			},
		},
		{
			name: "multimediaDevices",
			raw:  `{"signals": {"device": {"multimediaDevices": "NA"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintMultimediaDevices{}, fp.Signals.Device.MultimediaDevices)
			},
		},
		{
			name: "mediaQueries",
			raw:  `{"signals": {"device": {"mediaQueries": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintDeviceMediaQueries{}, fp.Signals.Device.MediaQueries)
			},
		},
		{
			name: "keyboard",
			raw:  `{"signals": {"device": {"keyboard": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintDeviceKeyboard{}, fp.Signals.Device.Keyboard)
			},
		},
		{
			name: "browser features",
			raw:  `{"signals": {"browser": {"userAgent": "curl/8", "features": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintBrowserFeatures{}, fp.Signals.Browser.Features)
				assert.Equal(t, "curl/8", fp.Signals.Browser.UserAgent)
			},
		},
		{
			name: "plugins",
			raw:  `{"signals": {"browser": {"plugins": "NA"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintBrowserPlugins{}, fp.Signals.Browser.Plugins)
			},
		},
		{
			name: "extensions",
			raw:  `{"signals": {"browser": {"extensions": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintBrowserExtensions{}, fp.Signals.Browser.Extensions)
			},
		},
		{
			name: "highEntropyValues",
			raw:  `{"signals": {"browser": {"highEntropyValues": "NA"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintBrowserHighEntropyValues{}, fp.Signals.Browser.HighEntropyValues)
			},
		},
		{
			name: "toSourceError",
			raw:  `{"signals": {"browser": {"toSourceError": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintBrowserToSourceError{}, fp.Signals.Browser.ToSourceError)
			},
		},
		{
			name: "ai",
			raw:  `{"signals": {"browser": {"ai": "NA"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintBrowserAI{}, fp.Signals.Browser.AI)
			},
		},
		{
			name: "webGL",
			raw:  `{"signals": {"graphics": {"webGL": "ERROR", "canvas": {"canvasFingerprint": "-421c84e0"}}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintGraphicsWebGL{}, fp.Signals.Graphics.WebGL)
				assert.Equal(t, "-421c84e0", fp.Signals.Graphics.Canvas.CanvasFingerprint)
			},
		},
		{
			name: "webgpu",
			raw:  `{"signals": {"graphics": {"webgpu": "NA"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintGraphicsWebGPU{}, fp.Signals.Graphics.WebGPU)
			},
		},
		{
			name: "canvas",
			raw:  `{"signals": {"graphics": {"canvas": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintGraphicsCanvas{}, fp.Signals.Graphics.Canvas)
			},
		},
		{
			name: "codecs",
			raw:  `{"signals": {"codecs": "ERROR"}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintCodecs{}, fp.Signals.Codecs)
			},
		},
		{
			name: "internationalization",
			raw:  `{"signals": {"locale": {"internationalization": "ERROR", "languages": {"language": "en"}}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintLocaleInternationalization{}, fp.Signals.Locale.Internationalization)
				assert.Equal(t, "en", fp.Signals.Locale.Languages.Language)
			},
		},
		{
			name: "languages",
			raw:  `{"signals": {"locale": {"languages": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintLocaleLanguages{}, fp.Signals.Locale.Languages)
			},
		},
		{
			name: "iframe",
			raw:  `{"signals": {"contexts": {"iframe": "ERROR"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintIframeContext{}, fp.Signals.Contexts.Iframe)
			},
		},
		{
			name: "webWorker",
			raw:  `{"signals": {"contexts": {"webWorker": "SKIPPED"}}}`,
			assertFP: func(t *testing.T, fp *FingerprintData) {
				assert.Equal(t, fingerprintWebWorkerContext{}, fp.Signals.Contexts.WebWorker)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &FingerprintData{}
			require.NoError(t, json.Unmarshal([]byte(tc.raw), fp))
			tc.assertFP(t, fp)
		})
	}
}

// Only the sentinel string is tolerated: anything else in an object slot is
// still a malformed payload.
func TestFlexStructRejectsNonString(t *testing.T) {
	fp := &FingerprintData{}
	require.Error(t, json.Unmarshal([]byte(`{"signals": {"device": {"screenResolution": 42}}}`), fp))
}

// The whole-object sentinel and the per-field sentinels the collectors emit
// (setObjectValues) have to survive together.
func TestFlexStructKeepsSiblingSignals(t *testing.T) {
	fp := mustUnmarshal(t, `{"signals": {"device": {
		"cpuCount": "ERROR",
		"platform": "MacIntel",
		"screenResolution": "ERROR",
		"keyboard": {"layout": "NA", "layoutSize": "NA"}
	}}, "fsid": "FS1_x", "fastBotDetection": true}`)

	assert.Equal(t, FlexInt(0), fp.Signals.Device.CPUCount)
	assert.Equal(t, "MacIntel", fp.Signals.Device.Platform)
	assert.Equal(t, fingerprintScreenResolution{}, fp.Signals.Device.ScreenResolution)
	assert.Equal(t, "NA", fp.Signals.Device.Keyboard.Layout)
	assert.Equal(t, "FS1_x", fp.FSID)
	assert.True(t, fp.IsBot())
}

// A dropped signal is the zero value of an unchanged struct, so it survives
// the cookie envelope like any other zero value — no proto shape change.
func TestFlexStructProtoRoundTrip(t *testing.T) {
	fp := mustUnmarshal(t, `{"signals": {
		"device": {"platform": "MacIntel", "screenResolution": "ERROR"},
		"graphics": {"webgpu": "NA"},
		"browser": {"highEntropyValues": "ERROR", "features": "ERROR"},
		"locale": {"languages": "ERROR"},
		"contexts": {"webWorker": "SKIPPED"}
	}}`)

	got := fingerprintDataFromProto(fp.ToProto())

	assert.Equal(t, fp.Signals, got.Signals)
}
