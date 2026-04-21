package challenge

import (
	"net/http"
	"strings"

	"golang.org/x/text/language"
)

// UAMobileMismatch reports whether the fingerprint's user-agent claims a
// mobile form factor while the reported inner viewport width is implausibly
// wide for a real device. Catches the "UA switcher set to Android while
// actually on a desktop" pattern.
//
// Returns false (no signal) when either the UA doesn't claim mobile or the
// inner width is zero/missing.
func (f *FingerprintData) UAMobileMismatch() bool {
	if f == nil {
		return false
	}

	ua := f.UserAgent()
	if ua == "" {
		return false
	}

	if !mobileUARegex.MatchString(ua) {
		return false
	}

	innerWidth := f.Signals.Device.ScreenResolution.InnerWidth.Int()
	if innerWidth <= 0 {
		return false
	}

	return innerWidth >= mobileViewportThreshold
}

// AcceptLanguageMismatch reports whether the request's Accept-Language
// header disagrees with the fingerprint's navigator.language. Both are
// derived from the same browser preference, so on a real browser they
// should agree at the base-language level.
//
// Returns false when either side is empty or unparseable — never a false
// positive on missing data.
//
// Deliberately different from the library's MismatchLanguages detection,
// which only compares navigator.languages[0] to navigator.language inside
// the browser; this helper brings the HTTP header into the comparison.
func (f *FingerprintData) AcceptLanguageMismatch(req *http.Request) bool {
	if f == nil || req == nil {
		return false
	}

	fpLang := f.Language()
	if fpLang == "" {
		return false
	}

	header := req.Header.Get("Accept-Language")
	if header == "" {
		return false
	}

	tags, _, err := language.ParseAcceptLanguage(header)
	if err != nil || len(tags) == 0 {
		return false
	}

	headerBase, _ := tags[0].Base()

	fpTag, err := language.Parse(fpLang)
	if err != nil {
		return false
	}

	fpBase, _ := fpTag.Base()

	return headerBase.String() != fpBase.String()
}

// TimezoneCountryMismatch reports whether the fingerprint's timezone
// disagrees with the client's country of origin (typically resolved via
// IPToCountry from the client IP).
//
// SOFT SIGNAL. Travelers whose OS timezone hasn't auto-adjusted and VPN
// users will legitimately trigger this. Rule authors should combine it
// with other signals (High()/Medium() counts, or reason-specific checks)
// before using it alone to ban.
//
// Returns false when either the timezone is unknown to our IANA table or
// the country is empty.
func (f *FingerprintData) TimezoneCountryMismatch(country string) bool {
	if f == nil || country == "" {
		return false
	}

	tz := f.Timezone()
	if tz == "" {
		return false
	}

	countries := lookupTimezoneCountries(tz)
	if len(countries) == 0 {
		return false
	}

	for _, c := range countries {
		if c == country {
			return false
		}
	}

	return true
}

// MismatchSignal is a single fired reason/severity pair on the report.
type MismatchSignal struct {
	Reason   string
	Severity string
}

// MismatchReport aggregates the fired mismatch signals for a single
// fingerprint evaluation. Returned by ComputeMismatchReport; typically
// accessed through the cached EvaluateMismatches closure in the
// on_challenge expr env.
type MismatchReport struct {
	Signals []MismatchSignal
}

// Count returns the total number of fired signals.
func (r *MismatchReport) Count() int {
	if r == nil {
		return 0
	}
	return len(r.Signals)
}

// Empty reports whether no signal fired.
func (r *MismatchReport) Empty() bool {
	return r.Count() == 0
}

// Has reports whether a signal with the given reason key is present.
func (r *MismatchReport) Has(reason string) bool {
	if r == nil {
		return false
	}
	for _, s := range r.Signals {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

// Reasons returns the stable-ordered list of fired reason keys.
func (r *MismatchReport) Reasons() []string {
	if r == nil {
		return nil
	}
	out := make([]string, len(r.Signals))
	for i, s := range r.Signals {
		out[i] = s.Reason
	}
	return out
}

// High returns the count of signals tagged with the "high" severity.
func (r *MismatchReport) High() int {
	return r.BySeverity(SeverityHigh)
}

// Medium returns the count of signals tagged with the "medium" severity.
func (r *MismatchReport) Medium() int {
	return r.BySeverity(SeverityMedium)
}

// Low returns the count of signals tagged with the "low" severity.
func (r *MismatchReport) Low() int {
	return r.BySeverity(SeverityLow)
}

// BySeverity returns the count of signals at the requested severity level.
func (r *MismatchReport) BySeverity(sev string) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, s := range r.Signals {
		if s.Severity == sev {
			n++
		}
	}
	return n
}

// String renders the report as "reason1(sev),reason2(sev)" for log lines.
func (r *MismatchReport) String() string {
	if r == nil || len(r.Signals) == 0 {
		return ""
	}
	var b strings.Builder
	for i, s := range r.Signals {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s.Reason)
		b.WriteByte('(')
		b.WriteString(s.Severity)
		b.WriteByte(')')
	}
	return b.String()
}

// ComputeMismatchReport walks the library-native bot alias plus the
// CrowdSec custom helpers and returns every fired signal in a stable
// order. It is the pure computation backing EvaluateMismatches; callers
// wanting caching + observability should use the env closure registered
// in GetOnChallengeEnv instead.
//
// `country` is the ISO-3166 alpha-2 code of the client's geolocated
// country, or "" when unknown. Pass `exprhelpers.IPToCountry(...)`'s
// return value (or equivalent) — resolved once at the call site so this
// method stays free of side-effects.
//
// Iteration order is libDetections first (in the order declared there),
// then customDetections. Reason / severity / accessor binding for every
// check lives in one place — fingerprint_mismatch_data.go.
func (f *FingerprintData) ComputeMismatchReport(req *http.Request, country string) *MismatchReport {
	report := &MismatchReport{}

	if f == nil {
		return report
	}

	for _, d := range libDetections {
		if d.Read(f.Bot) {
			report.Signals = append(report.Signals, MismatchSignal{
				Reason:   d.Key,
				Severity: d.Severity,
			})
		}
	}

	for _, d := range customDetections {
		if d.Fire(f, req, country) {
			report.Signals = append(report.Signals, MismatchSignal{
				Reason:   d.Key,
				Severity: d.Severity,
			})
		}
	}

	return report
}
