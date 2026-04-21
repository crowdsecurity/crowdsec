package challenge

import (
	"net/http"
	"regexp"
)

// Severity labels. Mirror the fpscanner library's fastBotDetectionDetails[*].severity
// strings so the vocabulary is consistent end-to-end.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// Stable reason keys. One per entry in libDetections / customDetections
// below. Kept as exported constants so rule authors can
// `Has("platform_mismatch")` without typos.
const (
	ReasonCDP                      = "cdp"
	ReasonWebdriver                = "webdriver"
	ReasonWebdriverWritable        = "webdriver_writable"
	ReasonSelenium                 = "selenium"
	ReasonPlaywright               = "playwright"
	ReasonWebdriverIframe          = "webdriver_iframe"
	ReasonWebdriverWorker          = "webdriver_worker"
	ReasonHeadlessScreenResolution = "headless_screen_resolution"
	ReasonMissingChromeObject      = "missing_chrome_object"
	ReasonImpossibleMemory         = "impossible_memory"
	ReasonHighCPUCount             = "high_cpu_count"
	ReasonMismatchWebGLWorker      = "mismatch_webgl_worker"
	ReasonMismatchPlatformIframe   = "mismatch_platform_iframe"
	ReasonMismatchPlatformWorker   = "mismatch_platform_worker"
	ReasonPlatformMismatch         = "platform_mismatch"
	ReasonGPUMismatch              = "gpu_mismatch"
	ReasonBotUserAgent             = "bot_user_agent"
	ReasonInconsistentEtsl         = "inconsistent_etsl"
	ReasonUAMobile                 = "ua_mobile"
	ReasonUTCTimezone              = "utc_timezone"
	ReasonAcceptLanguage           = "accept_language"
	ReasonSwiftshaderRenderer      = "swiftshader_renderer"
	ReasonMismatchLanguages        = "mismatch_languages"
	ReasonTimezoneCountry          = "timezone_country"
)

// libDetection binds an fpscanner-native signal to the bot-alias bool that
// carries its `detected` flag, together with our severity label for it.
//
// TODO: the fpscanner library ships each check with its own severity in the
// JSON payload. We don't unmarshal `severity` today (the struct only carries
// `detected`), so the severity values below are a mirror of what the library
// defaults to. When `fingerprintDetectionResult` grows a Severity field, we
// can drop the Severity column here and read it from the payload instead.
type libDetection struct {
	Key      string
	Severity string
	Read     func(fingerprintBotAlias) bool
}

// libDetections is the single source of truth for every library-native bot
// signal we surface: the reason key, its severity, and how to read its
// `detected` value from the bot alias. Append-only and ordering-stable so
// `MismatchReport.Reasons()` has a deterministic output.
var libDetections = []libDetection{
	{ReasonCDP, SeverityHigh, func(b fingerprintBotAlias) bool { return b.CDP }},
	{ReasonWebdriver, SeverityHigh, func(b fingerprintBotAlias) bool { return b.Webdriver }},
	{ReasonWebdriverWritable, SeverityHigh, func(b fingerprintBotAlias) bool { return b.WebdriverWritable }},
	{ReasonSelenium, SeverityHigh, func(b fingerprintBotAlias) bool { return b.Selenium }},
	{ReasonPlaywright, SeverityHigh, func(b fingerprintBotAlias) bool { return b.Playwright }},
	{ReasonWebdriverIframe, SeverityHigh, func(b fingerprintBotAlias) bool { return b.WebdriverIframe }},
	{ReasonWebdriverWorker, SeverityHigh, func(b fingerprintBotAlias) bool { return b.WebdriverWorker }},
	{ReasonHeadlessScreenResolution, SeverityHigh, func(b fingerprintBotAlias) bool { return b.HeadlessChromeScreenResolution }},
	{ReasonMissingChromeObject, SeverityHigh, func(b fingerprintBotAlias) bool { return b.MissingChromeObject }},
	{ReasonImpossibleMemory, SeverityHigh, func(b fingerprintBotAlias) bool { return b.ImpossibleDeviceMemory }},
	{ReasonHighCPUCount, SeverityHigh, func(b fingerprintBotAlias) bool { return b.HighCPUCount }},
	{ReasonMismatchWebGLWorker, SeverityHigh, func(b fingerprintBotAlias) bool { return b.MismatchWebGLInWorker }},
	{ReasonMismatchPlatformIframe, SeverityHigh, func(b fingerprintBotAlias) bool { return b.MismatchPlatformIframe }},
	{ReasonMismatchPlatformWorker, SeverityHigh, func(b fingerprintBotAlias) bool { return b.MismatchPlatformWorker }},
	{ReasonPlatformMismatch, SeverityHigh, func(b fingerprintBotAlias) bool { return b.PlatformMismatch }},
	{ReasonGPUMismatch, SeverityHigh, func(b fingerprintBotAlias) bool { return b.GPUMismatch }},
	{ReasonBotUserAgent, SeverityHigh, func(b fingerprintBotAlias) bool { return b.BotUserAgent }},
	{ReasonInconsistentEtsl, SeverityHigh, func(b fingerprintBotAlias) bool { return b.InconsistentEtsl }},
	{ReasonUTCTimezone, SeverityMedium, func(b fingerprintBotAlias) bool { return b.UTCTimezone }},
	{ReasonSwiftshaderRenderer, SeverityLow, func(b fingerprintBotAlias) bool { return b.SwiftshaderRenderer }},
	{ReasonMismatchLanguages, SeverityLow, func(b fingerprintBotAlias) bool { return b.MismatchLanguages }},
}

// customDetection binds a CrowdSec-authored mismatch helper (which may need
// request or geoip data) to its reason key and severity. The Fire function
// wraps whichever method-on-fp is the actual check — unified signature so
// customDetections can be iterated like libDetections.
type customDetection struct {
	Key      string
	Severity string
	Fire     func(fp *FingerprintData, req *http.Request, country string) bool
}

// customDetections lists every check we run on top of the library's own.
// Ordering is stable and comes after libDetections in the final report.
var customDetections = []customDetection{
	{
		Key:      ReasonUAMobile,
		Severity: SeverityMedium,
		Fire:     func(fp *FingerprintData, _ *http.Request, _ string) bool { return fp.UAMobileMismatch() },
	},
	{
		Key:      ReasonAcceptLanguage,
		Severity: SeverityMedium,
		Fire:     func(fp *FingerprintData, req *http.Request, _ string) bool { return fp.AcceptLanguageMismatch(req) },
	},
	{
		Key:      ReasonTimezoneCountry,
		Severity: SeverityLow,
		Fire:     func(fp *FingerprintData, _ *http.Request, country string) bool { return fp.TimezoneCountryMismatch(country) },
	},
}

// severityByReason is derived once at init from the two detection tables
// above. It exists so callers that only need the severity for a reason key
// (metric labels, tests, SeverityFor) don't have to walk the tables.
var severityByReason = buildSeverityByReason()

func buildSeverityByReason() map[string]string {
	m := make(map[string]string, len(libDetections)+len(customDetections))
	for _, d := range libDetections {
		m[d.Key] = d.Severity
	}
	for _, d := range customDetections {
		m[d.Key] = d.Severity
	}
	return m
}

// SeverityFor returns the severity tagged to a reason key, or "" for
// unknown reasons.
func SeverityFor(reason string) string {
	return severityByReason[reason]
}

// KnownReasons returns the full set of reason keys the aggregator may emit.
// Order is not guaranteed; callers that need deterministic ordering should
// walk libDetections / customDetections directly.
func KnownReasons() []string {
	out := make([]string, 0, len(severityByReason))
	for k := range severityByReason {
		out = append(out, k)
	}
	return out
}

// mobileUARegex matches UAs that claim a PHONE form factor. Deliberately
// does not match bare "Android", because per Google's UA convention the
// `Mobile` / `Mobi` token is what phones add and tablets omit. Matching
// Android alone would FP on every Android tablet in landscape and on
// Samsung DeX / Android desktop mode (UA keeps "Android", viewport is
// ≥1000px).
var mobileUARegex = regexp.MustCompile(`(?i)Mobi|iPhone|iPod`)

// mobileViewportThreshold is the innerWidth cutoff above which we treat a
// mobile-claiming UA as inconsistent. Real phones report CSS pixel widths
// well below this (typical phones: 360-430). Tablets run wider but don't
// match the UA regex above, so this threshold only applies to phone-UAs.
const mobileViewportThreshold = 1000
