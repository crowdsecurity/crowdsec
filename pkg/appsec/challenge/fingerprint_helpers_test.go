package challenge

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleFingerprintJSON = `{
  "signals": {
    "device": {
      "cpuCount": 14,
      "memory": 8,
      "platform": "MacIntel"
    },
    "browser": {
      "userAgent": "Mozilla/5.0 Chrome",
      "highEntropyValues": {
        "platform": "macOS",
        "mobile": false
      }
    },
    "locale": {
      "internationalization": {"timezone": "Europe/Paris"},
      "languages": {"language": "en", "languages": ["en","fr"]}
    }
  },
  "fsid": "FS1_abc",
  "nonce": "n1",
  "time": 1770669806462,
  "url": "http://localhost/",
  "fastBotDetection": true,
  "fastBotDetectionDetails": {
    "hasCDP":                   {"detected": true,  "severity": "high"},
    "headlessChromeScreenResolution": {"detected": false, "severity": "high"},
    "hasWebdriver":             {"detected": false, "severity": "high"},
    "hasWebdriverWritable":     {"detected": false, "severity": "high"},
    "hasSeleniumProperty":      {"detected": false, "severity": "high"},
    "hasPlaywright":            {"detected": false, "severity": "high"},
    "hasImpossibleDeviceMemory":{"detected": false, "severity": "high"},
    "hasHighCPUCount":          {"detected": false, "severity": "high"},
    "hasMissingChromeObject":   {"detected": false, "severity": "high"},
    "hasWebdriverIframe":       {"detected": false, "severity": "high"},
    "hasWebdriverWorker":       {"detected": false, "severity": "high"},
    "hasMismatchWebGLInWorker": {"detected": false, "severity": "high"},
    "hasMismatchPlatformIframe":{"detected": false, "severity": "high"},
    "hasMismatchPlatformWorker":{"detected": false, "severity": "high"},
    "hasSwiftshaderRenderer":   {"detected": false, "severity": "low"},
    "hasUTCTimezone":           {"detected": false, "severity": "medium"}
  }
}`

func TestFingerprintHelpers_Getters(t *testing.T) {
	var fp FingerprintData
	require.NoError(t, json.Unmarshal([]byte(sampleFingerprintJSON), &fp))

	assert.True(t, fp.IsBot())
	assert.True(t, fp.HasBotSignal())
	assert.Equal(t, 1, fp.BotSignalCount())

	// only CDP is set in the sample, so only HasAutomationSignal should flip
	assert.True(t, fp.HasAutomationSignal())
	assert.False(t, fp.HasHeadlessSignal())
	assert.False(t, fp.HasMismatchSignal())
	assert.False(t, fp.HasImpossibleDeviceSignal())

	assert.Equal(t, "Mozilla/5.0 Chrome", fp.UserAgent())
	assert.Equal(t, "macOS", fp.Platform()) // prefers high-entropy value
	assert.Equal(t, "Europe/Paris", fp.Timezone())
	assert.Equal(t, "en", fp.Language())
	assert.False(t, fp.IsMobile())
	assert.Equal(t, 14, fp.CPUCount())
	assert.Equal(t, 8, fp.Memory())
}

func TestFingerprintHelpers_PlatformFallback(t *testing.T) {
	// no high-entropy platform -> falls back to navigator.platform
	fp := FingerprintData{}
	fp.Signals.Device.Platform = "Linux x86_64"
	assert.Equal(t, "Linux x86_64", fp.Platform())
}

func TestFingerprintHelpers_NilReceiver(t *testing.T) {
	var fp *FingerprintData

	assert.False(t, fp.IsBot())
	assert.False(t, fp.HasBotSignal())
	assert.Equal(t, 0, fp.BotSignalCount())
	assert.False(t, fp.HasAutomationSignal())
	assert.False(t, fp.HasHeadlessSignal())
	assert.False(t, fp.HasMismatchSignal())
	assert.False(t, fp.HasImpossibleDeviceSignal())
	assert.Equal(t, "", fp.UserAgent())
	assert.Equal(t, "", fp.Platform())
	assert.Equal(t, "", fp.Timezone())
	assert.Equal(t, "", fp.Language())
	assert.False(t, fp.IsMobile())
	assert.Equal(t, 0, fp.CPUCount())
	assert.Equal(t, 0, fp.Memory())
}

func TestFingerprintHelpers_CategoryAggregates(t *testing.T) {
	const (
		catAutomation       = "automation"
		catHeadless         = "headless"
		catMismatch         = "mismatch"
		catImpossibleDevice = "impossible_device"
	)

	cases := []struct {
		name string
		set  func(*fingerprintBotAlias)
		want string
	}{
		{"webdriver", func(b *fingerprintBotAlias) { b.Webdriver = true }, catAutomation},
		{"webdriverWritable", func(b *fingerprintBotAlias) { b.WebdriverWritable = true }, catAutomation},
		{"selenium", func(b *fingerprintBotAlias) { b.Selenium = true }, catAutomation},
		{"cdp", func(b *fingerprintBotAlias) { b.CDP = true }, catAutomation},
		{"playwright", func(b *fingerprintBotAlias) { b.Playwright = true }, catAutomation},

		{"headlessChromeScreenResolution", func(b *fingerprintBotAlias) { b.HeadlessChromeScreenResolution = true }, catHeadless},
		{"missingChromeObject", func(b *fingerprintBotAlias) { b.MissingChromeObject = true }, catHeadless},
		{"swiftshaderRenderer", func(b *fingerprintBotAlias) { b.SwiftshaderRenderer = true }, catHeadless},

		{"mismatchWebGLInWorker", func(b *fingerprintBotAlias) { b.MismatchWebGLInWorker = true }, catMismatch},
		{"mismatchPlatformIframe", func(b *fingerprintBotAlias) { b.MismatchPlatformIframe = true }, catMismatch},
		{"mismatchPlatformWorker", func(b *fingerprintBotAlias) { b.MismatchPlatformWorker = true }, catMismatch},
		{"webdriverIframe", func(b *fingerprintBotAlias) { b.WebdriverIframe = true }, catMismatch},
		{"webdriverWorker", func(b *fingerprintBotAlias) { b.WebdriverWorker = true }, catMismatch},

		{"impossibleDeviceMemory", func(b *fingerprintBotAlias) { b.ImpossibleDeviceMemory = true }, catImpossibleDevice},
		{"highCPUCount", func(b *fingerprintBotAlias) { b.HighCPUCount = true }, catImpossibleDevice},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &FingerprintData{}
			tc.set(&fp.Bot)

			got := map[string]bool{
				catAutomation:       fp.HasAutomationSignal(),
				catHeadless:         fp.HasHeadlessSignal(),
				catMismatch:         fp.HasMismatchSignal(),
				catImpossibleDevice: fp.HasImpossibleDeviceSignal(),
			}

			for cat, fired := range got {
				if cat == tc.want {
					assert.True(t, fired, "expected category %q to fire", cat)
				} else {
					assert.False(t, fired, "expected category %q to stay false", cat)
				}
			}
		})
	}
}
