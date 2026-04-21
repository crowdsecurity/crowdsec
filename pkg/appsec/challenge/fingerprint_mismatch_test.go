package challenge

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// androidOnLinuxSample is the user-provided fingerprint with a spoofed
// Android/Firefox UA on a real Chromium-on-Linux environment. It's kept
// verbatim as a permanent regression fixture.
const androidOnLinuxSample = `{
  "signals": {
    "automation": {"webdriver": false, "cdp": true},
    "device": {
      "cpuCount": 16,
      "memory": 8,
      "platform": "Linux x86_64",
      "screenResolution": {
        "width": 1920, "height": 1080,
        "innerWidth": 1920, "innerHeight": 993
      }
    },
    "browser": {
      "userAgent": "Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0",
      "features": {"chrome": true},
      "highEntropyValues": {"platform": "", "mobile": false}
    },
    "locale": {
      "internationalization": {"timezone": "Europe/Paris"},
      "languages": {"language": "en-US", "languages": ["en-US"]}
    }
  },
  "fsid": "FS_SAMPLE",
  "nonce": "n",
  "time": 1776669341379,
  "url": "https://example/",
  "fastBotDetection": true,
  "fastBotDetectionDetails": {
    "hasCDP":                   {"detected": true,  "severity": "high"},
    "hasInconsistentEtsl":      {"detected": true,  "severity": "high"},
    "hasPlatformMismatch":      {"detected": true,  "severity": "high"},
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
    "hasUTCTimezone":           {"detected": false, "severity": "medium"},
    "hasMismatchLanguages":     {"detected": false, "severity": "low"},
    "hasBotUserAgent":          {"detected": false, "severity": "high"},
    "hasGPUMismatch":           {"detected": false, "severity": "high"}
  }
}`

func mustUnmarshal(t *testing.T, raw string) *FingerprintData {
	t.Helper()
	fp := &FingerprintData{}
	require.NoError(t, json.Unmarshal([]byte(raw), fp))
	return fp
}

func TestUAMobileMismatch(t *testing.T) {
	cases := []struct {
		name       string
		ua         string
		innerWidth int
		want       bool
	}{
		{"android phone UA desktop viewport", "Mozilla/5.0 (Android 4.4; Mobile; rv:70.0)", 1920, true},
		{"iphone UA huge viewport", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)", 1440, true},
		{"real android phone small viewport", "Mozilla/5.0 (Linux; Android 14; Pixel 7) Mobile", 412, false},
		{"desktop UA desktop viewport", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120", 1920, false},
		{"mobile UA missing innerWidth", "Mozilla/5.0 (Android 10; Mobile)", 0, false},
		{"empty UA", "", 1920, false},
		// Regression: a real Android tablet UA lacks the "Mobile" token by
		// Google's convention. Its landscape viewport is wider than 1000px.
		// Must NOT fire — previously a FP when the regex matched bare "Android".
		{"android tablet landscape", "Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36", 1280, false},
		// Regression: Samsung DeX / Android desktop mode keeps "Android" in
		// the UA but the user is on a desktop-sized screen. Must NOT fire.
		{"samsung dex desktop viewport", "Mozilla/5.0 (Linux; Android 13; SM-S908U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36", 1920, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &FingerprintData{}
			fp.Signals.Browser.UserAgent = tc.ua
			fp.Signals.Device.ScreenResolution.InnerWidth = FlexInt(tc.innerWidth)
			assert.Equal(t, tc.want, fp.UAMobileMismatch())
		})
	}

	var nilFP *FingerprintData
	assert.False(t, nilFP.UAMobileMismatch())
}

func TestAcceptLanguageMismatch(t *testing.T) {
	cases := []struct {
		name   string
		header string
		fpLang string
		want   bool
	}{
		{"match en simple", "en-US,fr;q=0.8", "en", false},
		{"match fr simple", "fr-FR,fr;q=0.9,en;q=0.5", "fr", false},
		{"mismatch de vs en", "de-DE,de;q=0.9", "en", true},
		{"mismatch zh vs en", "zh-CN", "en-US", true},
		{"missing header", "", "en", false},
		{"missing fp lang", "en-US", "", false},
		{"garbage header", "@@@", "en", false},
		{"garbage fp lang", "en-US", "@@@", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &FingerprintData{}
			fp.Signals.Locale.Languages.Language = tc.fpLang

			req, err := http.NewRequest("GET", "http://x/", nil)
			require.NoError(t, err)
			if tc.header != "" {
				req.Header.Set("Accept-Language", tc.header)
			}

			assert.Equal(t, tc.want, fp.AcceptLanguageMismatch(req))
		})
	}

	var nilFP *FingerprintData
	assert.False(t, nilFP.AcceptLanguageMismatch(nil))
}

func TestTimezoneCountryMismatch(t *testing.T) {
	cases := []struct {
		name    string
		tz      string
		country string
		want    bool
	}{
		{"paris in france", "Europe/Paris", "FR", false},
		{"paris for monaco too", "Europe/Paris", "MC", false},
		{"paris claimed from US", "Europe/Paris", "US", true},
		{"new york in us", "America/New_York", "US", false},
		{"new york claimed from fr", "America/New_York", "FR", true},
		{"alias calcutta", "Asia/Calcutta", "IN", false},
		{"alias kiev", "Europe/Kiev", "UA", false},
		{"unknown tz", "Made/Up", "FR", false},
		{"empty country", "Europe/Paris", "", false},
		{"empty tz", "", "FR", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &FingerprintData{}
			fp.Signals.Locale.Internationalization.Timezone = tc.tz
			assert.Equal(t, tc.want, fp.TimezoneCountryMismatch(tc.country))
		})
	}

	var nilFP *FingerprintData
	assert.False(t, nilFP.TimezoneCountryMismatch("FR"))
}

func TestMismatchReport_Helpers(t *testing.T) {
	r := &MismatchReport{Signals: []MismatchSignal{
		{Reason: ReasonCDP, Severity: SeverityHigh},
		{Reason: ReasonPlatformMismatch, Severity: SeverityHigh},
		{Reason: ReasonAcceptLanguage, Severity: SeverityMedium},
		{Reason: ReasonTimezoneCountry, Severity: SeverityLow},
	}}

	assert.Equal(t, 4, r.Count())
	assert.False(t, r.Empty())
	assert.Equal(t, 2, r.High())
	assert.Equal(t, 1, r.Medium())
	assert.Equal(t, 1, r.Low())
	assert.Equal(t, 2, r.BySeverity(SeverityHigh))
	assert.True(t, r.Has(ReasonCDP))
	assert.False(t, r.Has(ReasonBotUserAgent))
	assert.Equal(t, []string{ReasonCDP, ReasonPlatformMismatch, ReasonAcceptLanguage, ReasonTimezoneCountry}, r.Reasons())
	assert.Equal(t,
		"cdp(high),platform_mismatch(high),accept_language(medium),timezone_country(low)",
		r.String(),
	)
}

func TestMismatchReport_NilReceiver(t *testing.T) {
	var r *MismatchReport
	assert.Equal(t, 0, r.Count())
	assert.True(t, r.Empty())
	assert.False(t, r.Has(ReasonCDP))
	assert.Nil(t, r.Reasons())
	assert.Equal(t, 0, r.High())
	assert.Equal(t, 0, r.Medium())
	assert.Equal(t, 0, r.Low())
	assert.Equal(t, "", r.String())
}

func TestComputeMismatchReport_AndroidOnLinuxSample(t *testing.T) {
	fp := mustUnmarshal(t, androidOnLinuxSample)

	req, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)

	// Request originates from France; timezone is also Europe/Paris, so
	// timezone_country should NOT fire. The Android-UA + 1920 viewport
	// should fire ua_mobile, and the library-native detections fire cdp,
	// inconsistent_etsl, platform_mismatch.
	report := fp.ComputeMismatchReport(req, "FR")

	assert.Equal(t, []string{
		ReasonCDP,
		ReasonPlatformMismatch,
		ReasonInconsistentEtsl,
		ReasonUAMobile,
	}, report.Reasons())
	assert.Equal(t, 3, report.High())
	assert.Equal(t, 1, report.Medium(), "ua_mobile is medium severity")
	assert.Equal(t, 0, report.Low())
}

func TestComputeMismatchReport_BaselineConsistent(t *testing.T) {
	// Minimal consistent fingerprint — no library detections, consistent
	// UA/platform, en Accept-Language, FR timezone, from FR.
	raw := `{
      "signals": {
        "device": {"platform": "MacIntel"},
        "browser": {
          "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120",
          "highEntropyValues": {"platform": "macOS", "mobile": false}
        },
        "locale": {
          "internationalization": {"timezone": "Europe/Paris"},
          "languages": {"language": "en"}
        }
      },
      "fsid": "FS_OK", "nonce": "n", "time": 1, "url": "http://x/",
      "fastBotDetection": false,
      "fastBotDetectionDetails": {}
    }`
	fp := mustUnmarshal(t, raw)

	req, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	report := fp.ComputeMismatchReport(req, "FR")
	assert.True(t, report.Empty())
}

func TestComputeMismatchReport_AcceptLanguageOnly(t *testing.T) {
	raw := `{
      "signals": {
        "device": {"platform": "MacIntel"},
        "browser": {
          "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120",
          "highEntropyValues": {"platform": "macOS"}
        },
        "locale": {
          "internationalization": {"timezone": "Europe/Paris"},
          "languages": {"language": "en"}
        }
      },
      "fsid": "X", "nonce": "n", "time": 1, "url": "http://x/",
      "fastBotDetection": false,
      "fastBotDetectionDetails": {}
    }`
	fp := mustUnmarshal(t, raw)

	req, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")

	report := fp.ComputeMismatchReport(req, "FR")
	assert.Equal(t, []string{ReasonAcceptLanguage}, report.Reasons())
	assert.Equal(t, 0, report.High())
	assert.Equal(t, 1, report.Medium())
	assert.Equal(t, 0, report.Low())
}

func TestComputeMismatchReport_TimezoneCountryOnly(t *testing.T) {
	raw := `{
      "signals": {
        "device": {"platform": "MacIntel"},
        "browser": {
          "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120",
          "highEntropyValues": {"platform": "macOS"}
        },
        "locale": {
          "internationalization": {"timezone": "Europe/Paris"},
          "languages": {"language": "en"}
        }
      },
      "fsid": "X", "nonce": "n", "time": 1, "url": "http://x/",
      "fastBotDetection": false,
      "fastBotDetectionDetails": {}
    }`
	fp := mustUnmarshal(t, raw)

	req, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Language", "en-US")

	// Europe/Paris but client IP geolocated in the US.
	report := fp.ComputeMismatchReport(req, "US")
	assert.Equal(t, []string{ReasonTimezoneCountry}, report.Reasons())
	assert.Equal(t, 0, report.High())
	assert.Equal(t, 0, report.Medium())
	assert.Equal(t, 1, report.Low())
}

func TestComputeMismatchReport_NilFingerprint(t *testing.T) {
	report := ((*FingerprintData)(nil)).ComputeMismatchReport(nil, "")
	assert.True(t, report.Empty())
}

func TestSeverityFor(t *testing.T) {
	assert.Equal(t, SeverityHigh, SeverityFor(ReasonCDP))
	assert.Equal(t, SeverityMedium, SeverityFor(ReasonAcceptLanguage))
	assert.Equal(t, SeverityLow, SeverityFor(ReasonTimezoneCountry))
	assert.Equal(t, "", SeverityFor("not_a_reason"))
}
