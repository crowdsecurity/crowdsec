package appsec

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

// Well-known MaxMind test vectors that exist in the test mmdb under
// pkg/parser/testdata. Used to exercise the geoip-backed country
// resolution inside EvaluateMismatches without mocks.
const (
	testIPUS = "216.160.83.56" // Milton, US
	testIPGB = "81.2.69.142"   // London, GB
)

// setupGeoIP loads the same test mmdb the parser tests use so that
// IPToCountryString has a working reader to query. Safe to call more than
// once in a single test run.
func setupGeoIP(t *testing.T) {
	t.Helper()
	require.NoError(t, exprhelpers.GeoIPInit("../parser/testdata/"), "geoip init failed")
}

// fpEuropeParisCDP returns a fingerprint with Europe/Paris timezone and a
// single fired library signal (CDP), so EvaluateMismatches can be driven
// predictably.
func fpEuropeParisCDP(t *testing.T) *challenge.FingerprintData {
	t.Helper()
	raw := `{
      "signals": {
        "device": {"platform": "MacIntel"},
        "browser": {
          "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120",
          "highEntropyValues": {"platform": "macOS"}
        },
        "locale": {
          "internationalization": {"timezone": "Europe/Paris"},
          "languages": {"language": "en"}
        }
      },
      "fsid": "FS_RUNTIME", "nonce": "n", "time": 1, "url": "http://x/",
      "fastBotDetection": true,
      "fastBotDetectionDetails": {
        "hasCDP": {"detected": true, "severity": "high"}
      }
    }`
	fp := &challenge.FingerprintData{}
	require.NoError(t, json.Unmarshal([]byte(raw), fp))
	return fp
}

func makeRuntime() *AppsecRuntimeConfig {
	return &AppsecRuntimeConfig{Logger: log.NewEntry(log.StandardLogger())}
}

func TestEvaluateMismatches_GeoIPTimezoneMismatch_Fires(t *testing.T) {
	setupGeoIP(t)
	metrics.AppsecFingerprintMismatch.Reset()

	w := makeRuntime()
	httpReq, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)

	state := &AppsecRequestState{Fingerprint: fpEuropeParisCDP(t)}
	req := &ParsedRequest{
		HTTPRequest:  httpReq,
		ClientIP:     testIPUS, // geoip resolves to "US"
		AppsecEngine: "test-engine",
	}

	report := w.EvaluateMismatches(state, req)

	// Europe/Paris fingerprint timezone but request geoips to US → the
	// soft timezone_country signal must fire. CDP already fires from the
	// library side.
	assert.True(t, report.Has(challenge.ReasonTimezoneCountry),
		"expected timezone_country to fire for Europe/Paris + US geoip")
	assert.True(t, report.Has(challenge.ReasonCDP))
	assert.Equal(t, 1, report.High(), "only CDP is high severity here")
	assert.Equal(t, 1, report.Low(), "timezone_country is low severity")

	// Prometheus counters must reflect one bump per fired signal.
	assert.Equal(t, 1.0, testutil.ToFloat64(
		metrics.AppsecFingerprintMismatch.With(prometheus.Labels{
			"reason":        challenge.ReasonTimezoneCountry,
			"severity":      challenge.SeverityLow,
			"appsec_engine": "test-engine",
		}),
	))
	assert.Equal(t, 1.0, testutil.ToFloat64(
		metrics.AppsecFingerprintMismatch.With(prometheus.Labels{
			"reason":        challenge.ReasonCDP,
			"severity":      challenge.SeverityHigh,
			"appsec_engine": "test-engine",
		}),
	))
}

func TestEvaluateMismatches_GeoIPConsistent_NoTimezoneSignal(t *testing.T) {
	setupGeoIP(t)
	metrics.AppsecFingerprintMismatch.Reset()

	w := makeRuntime()
	httpReq, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)

	// Browser reports Europe/London tz; client IP geolocates to GB.
	// No timezone_country mismatch should fire.
	raw := `{
      "signals": {
        "device": {"platform": "Win32"},
        "browser": {
          "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
          "highEntropyValues": {"platform": "Windows"}
        },
        "locale": {
          "internationalization": {"timezone": "Europe/London"},
          "languages": {"language": "en"}
        }
      },
      "fsid": "FS_OK_GB", "nonce": "n", "time": 1, "url": "http://x/",
      "fastBotDetection": false,
      "fastBotDetectionDetails": {}
    }`
	fp := &challenge.FingerprintData{}
	require.NoError(t, json.Unmarshal([]byte(raw), fp))

	state := &AppsecRequestState{Fingerprint: fp}
	req := &ParsedRequest{
		HTTPRequest:  httpReq,
		ClientIP:     testIPGB, // geoip resolves to "GB"
		AppsecEngine: "test-engine",
	}

	report := w.EvaluateMismatches(state, req)

	assert.False(t, report.Has(challenge.ReasonTimezoneCountry),
		"Europe/London + GB geoip must not fire timezone_country")
	assert.True(t, report.Empty(), "no signals expected at all")
}

func TestEvaluateMismatches_CachesAcrossCalls(t *testing.T) {
	setupGeoIP(t)
	metrics.AppsecFingerprintMismatch.Reset()

	w := makeRuntime()
	httpReq, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)

	state := &AppsecRequestState{Fingerprint: fpEuropeParisCDP(t)}
	req := &ParsedRequest{
		HTTPRequest:  httpReq,
		ClientIP:     testIPUS,
		AppsecEngine: "test-engine",
	}

	first := w.EvaluateMismatches(state, req)
	second := w.EvaluateMismatches(state, req)
	third := w.EvaluateMismatches(state, req)

	// All three calls must return the exact same pointer — state cache.
	assert.Same(t, first, second)
	assert.Same(t, second, third)
	assert.Same(t, first, state.LastMismatchReport)

	// Observability fires once total (log + metric) despite three calls.
	// Verifies the emitMismatchObservability gate at state.LastMismatchReport.
	assert.Equal(t, 1.0, testutil.ToFloat64(
		metrics.AppsecFingerprintMismatch.With(prometheus.Labels{
			"reason":        challenge.ReasonTimezoneCountry,
			"severity":      challenge.SeverityLow,
			"appsec_engine": "test-engine",
		}),
	))
}

func TestEvaluateMismatches_UnresolvableClientIP_NoTimezoneSignal(t *testing.T) {
	setupGeoIP(t)
	metrics.AppsecFingerprintMismatch.Reset()

	w := makeRuntime()
	httpReq, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)

	state := &AppsecRequestState{Fingerprint: fpEuropeParisCDP(t)}
	req := &ParsedRequest{
		HTTPRequest:  httpReq,
		ClientIP:     "203.0.113.1", // not in the test mmdb
		AppsecEngine: "test-engine",
	}

	report := w.EvaluateMismatches(state, req)

	// With country == "" the timezone_country helper declines to decide,
	// so only the library CDP signal fires.
	assert.False(t, report.Has(challenge.ReasonTimezoneCountry))
	assert.True(t, report.Has(challenge.ReasonCDP))
}

func TestEvaluateMismatches_EmptyReport_NoObservability(t *testing.T) {
	setupGeoIP(t)
	metrics.AppsecFingerprintMismatch.Reset()

	w := makeRuntime()
	httpReq, err := http.NewRequest("GET", "http://x/", nil)
	require.NoError(t, err)

	// Consistent fingerprint — no library signals, no custom helper fires.
	raw := `{
      "signals": {
        "device": {"platform": "Win32"},
        "browser": {
          "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
          "highEntropyValues": {"platform": "Windows"}
        },
        "locale": {
          "internationalization": {"timezone": "Europe/London"},
          "languages": {"language": "en"}
        }
      },
      "fsid": "X", "nonce": "n", "time": 1, "url": "http://x/",
      "fastBotDetection": false,
      "fastBotDetectionDetails": {}
    }`
	fp := &challenge.FingerprintData{}
	require.NoError(t, json.Unmarshal([]byte(raw), fp))

	state := &AppsecRequestState{Fingerprint: fp}
	req := &ParsedRequest{
		HTTPRequest:  httpReq,
		ClientIP:     testIPGB,
		AppsecEngine: "test-engine",
	}

	report := w.EvaluateMismatches(state, req)
	assert.True(t, report.Empty())

	// No metric bump for any reason when the report is empty.
	for _, reason := range challenge.KnownReasons() {
		sev := challenge.SeverityFor(reason)
		got := testutil.ToFloat64(metrics.AppsecFingerprintMismatch.With(prometheus.Labels{
			"reason":        reason,
			"severity":      sev,
			"appsec_engine": "test-engine",
		}))
		assert.Equal(t, 0.0, got, "no counter bump expected for %q", reason)
	}
}
