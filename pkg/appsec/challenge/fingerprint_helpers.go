package challenge

import (
	log "github.com/sirupsen/logrus"
)

// Handwritten helpers on *FingerprintData. Kept in a dedicated file (not
// fingerprint.go) so a future fpscanner library bump — which rewrites the
// data-shape structs — doesn't clobber these methods.

// IsBot returns the library's fast-bot verdict as a native bool, so rules can write
// `fingerprint.IsBot()` instead of `fingerprint.FastBotDetection.Bool() == true`.
func (f *FingerprintData) IsBot() bool {
	if f == nil {
		return false
	}

	return bool(f.FastBotDetection)
}

// BotSignalCount returns the number of fast-bot-detection signals that fired.
func (f *FingerprintData) BotSignalCount() int {
	if f == nil {
		return 0
	}

	return f.Bot.DetectedCount.Int()
}

// HasBotSignal returns true if any fast-bot-detection signal fired.
func (f *FingerprintData) HasBotSignal() bool {
	if f == nil {
		return false
	}

	return f.Bot.AnyDetected
}

// HasAutomationSignal returns true if any automation-framework signal fired
// (webdriver, selenium, CDP, playwright, bot user-agent regex).
func (f *FingerprintData) HasAutomationSignal() bool {
	if f == nil {
		return false
	}

	b := f.Bot

	return b.Webdriver ||
		b.WebdriverWritable ||
		b.Selenium ||
		b.CDP ||
		b.Playwright ||
		b.BotUserAgent
}

// HasHeadlessSignal returns true if any headless-browser signal fired. Also
// folds in inconsistent-etsl, which fires when the TLS-level `etsl` integer
// disagrees with the claimed browser family — characteristic of patched /
// forged headless environments.
func (f *FingerprintData) HasHeadlessSignal() bool {
	if f == nil {
		return false
	}

	b := f.Bot

	return b.HeadlessChromeScreenResolution ||
		b.MissingChromeObject ||
		b.SwiftshaderRenderer ||
		b.InconsistentEtsl
}

// HasMismatchSignal returns true if any cross-context or cross-API mismatch
// signal fired (iframe/worker webdriver, platform, WebGL in worker, UA-vs-
// navigator platform, GPU, languages).
func (f *FingerprintData) HasMismatchSignal() bool {
	if f == nil {
		return false
	}

	b := f.Bot

	return b.MismatchWebGLInWorker ||
		b.MismatchPlatformIframe ||
		b.MismatchPlatformWorker ||
		b.WebdriverIframe ||
		b.WebdriverWorker ||
		b.PlatformMismatch ||
		b.GPUMismatch ||
		b.MismatchLanguages
}

// HasImpossibleDeviceSignal returns true if the reported device specs are outside
// plausible bounds (memory / CPU count).
func (f *FingerprintData) HasImpossibleDeviceSignal() bool {
	if f == nil {
		return false
	}

	b := f.Bot

	return b.ImpossibleDeviceMemory || b.HighCPUCount
}

// UserAgent returns the user-agent reported by the browser.
func (f *FingerprintData) UserAgent() string {
	if f == nil {
		return ""
	}

	return f.Signals.Browser.UserAgent
}

// Platform returns the browser-reported platform, preferring the high-entropy
// client-hint value and falling back to navigator.platform.
func (f *FingerprintData) Platform() string {
	if f == nil {
		return ""
	}

	if p := f.Signals.Browser.HighEntropyValues.Platform; p != "" {
		return p
	}

	return f.Signals.Device.Platform
}

// Timezone returns the browser-reported IANA timezone.
func (f *FingerprintData) Timezone() string {
	if f == nil {
		return ""
	}

	return f.Signals.Locale.Internationalization.Timezone
}

// Language returns the browser's primary language.
func (f *FingerprintData) Language() string {
	if f == nil {
		return ""
	}

	return f.Signals.Locale.Languages.Language
}

// IsMobile returns true if the browser advertises a mobile form factor
// (via UA client hints).
func (f *FingerprintData) IsMobile() bool {
	if f == nil {
		return false
	}

	return bool(f.Signals.Browser.HighEntropyValues.Mobile)
}

// CPUCount returns navigator.hardwareConcurrency as a native int.
func (f *FingerprintData) CPUCount() int {
	if f == nil {
		return 0
	}

	return f.Signals.Device.CPUCount.Int()
}

// Memory returns navigator.deviceMemory as a native int.
func (f *FingerprintData) Memory() int {
	if f == nil {
		return 0
	}

	return f.Signals.Device.Memory.Int()
}

// BotSignals returns the names of every library-native bot-detection signal
// that fired on this fingerprint (e.g. "webdriver", "cdp",
// "headless_screen_resolution", "platform_mismatch"). The slice is empty
// when nothing fired. Ordering matches libDetections and is therefore
// stable across calls, which keeps log output deterministic.
//
// Only signals carried directly by f.Bot are returned: the custom
// CrowdSec mismatches in customDetections need request/geo context that
// is not on FingerprintData and are surfaced separately via
// MismatchReport.
func (f *FingerprintData) BotSignals() []string {
	if f == nil {
		return nil
	}

	out := make([]string, 0, len(libDetections))

	for _, d := range libDetections {
		if d.Read(f.Bot) {
			out = append(out, d.Key)
		}
	}

	return out
}

// FingerprintLogVerbosity controls how much of a fingerprint is included
// in accept/reject log entries.
type FingerprintLogVerbosity int

const (
	// FingerprintLogMinimal: source, fsid, ua, platform, is_bot, signals,
	// allowlisted (and allowlist_reason when allowlisted). This is the
	// default when verbosity is omitted.
	FingerprintLogMinimal FingerprintLogVerbosity = iota
	// FingerprintLogInfo: minimal + is_mobile and the category roll-ups
	// (automation/headless/mismatch/impossible_device) when they fired.
	// This is the default tier surfaced to expr helpers as the string
	// "info".
	FingerprintLogInfo
	// FingerprintLogVerbose: info + timezone, language, cpu_count,
	// memory, url, nonce, fp_time.
	FingerprintLogVerbose
)

// resolveVerbosity returns the verbosity to use, defaulting to
// FingerprintLogMinimal when the variadic argument is omitted.
func resolveVerbosity(verbosity []FingerprintLogVerbosity) FingerprintLogVerbosity {
	if len(verbosity) == 0 {
		return FingerprintLogMinimal
	}

	return verbosity[0]
}

// LogAccepted emits a single structured log line for a fingerprint we
// are accepting (valid cookie, successful submission, allowlist grant).
//
// clientIP is the real visitor address (typically request.ClientIP, set
// by the bouncer via X-Forwarded-For or equivalent) and is logged as
// "source". bouncerIP is the connection-level peer of the appsec listener
// (typically request.RemoteAddrNormalized) and is logged as "bouncer".
// Both are needed: operators correlate visitor behavior on "source", but
// "bouncer" is what they use to debug which gateway forwarded the request
// (multi-WAF setups, misconfigured X-Forwarded-For chains, etc.).
//
// The caller picks the level — typically Debug for per-request sites and
// Info for rarer events. verbosity defaults to FingerprintLogMinimal.
func (f *FingerprintData) LogAccepted(logger *log.Entry, level log.Level, clientIP, bouncerIP, msg string, verbosity ...FingerprintLogVerbosity) {
	if f == nil || logger == nil {
		return
	}

	emitFingerprintLog(logger.WithFields(f.logFieldsAccept(clientIP, bouncerIP, resolveVerbosity(verbosity))), level, msg)
}

// LogRejected emits a single structured log line for a fingerprint we
// are rejecting.
//
// reason is the operator-facing rejection cause and is always included
// regardless of verbosity. clientIP is logged as "source", bouncerIP as
// "bouncer" — see LogAccepted for the rationale. Only positive
// information is included — negative facts ("not headless", "0 mismatches")
// are omitted because they are noise on a reject log.
func (f *FingerprintData) LogRejected(logger *log.Entry, level log.Level, clientIP, bouncerIP, reason, msg string, verbosity ...FingerprintLogVerbosity) {
	if f == nil || logger == nil {
		return
	}

	emitFingerprintLog(logger.WithFields(f.logFieldsReject(clientIP, bouncerIP, reason, resolveVerbosity(verbosity))), level, msg)
}

// emitFingerprintLog dispatches a message to the right logrus method for
// the requested level. Unknown levels fall back to Info so a typo can
// never silently drop the log.
func emitFingerprintLog(entry *log.Entry, level log.Level, msg string) {
	switch level {
	case log.PanicLevel, log.FatalLevel, log.ErrorLevel:
		entry.Error(msg)
	case log.WarnLevel:
		entry.Warn(msg)
	case log.DebugLevel:
		entry.Debug(msg)
	case log.TraceLevel:
		entry.Trace(msg)
	default:
		entry.Info(msg)
	}
}

// logFieldsAccept builds the structured field set for an accept log.
// Empty-string fields are omitted so partial fingerprints stay compact.
func (f *FingerprintData) logFieldsAccept(clientIP, bouncerIP string, v FingerprintLogVerbosity) log.Fields {
	fields := log.Fields{
		"is_bot":      f.IsBot(),
		"signals":     f.BotSignals(),
		"allowlisted": f.Allowlisted,
	}

	addCommonFingerprintFields(fields, f, clientIP, bouncerIP)

	if f.Allowlisted && f.AllowlistReason != "" {
		fields["allowlist_reason"] = f.AllowlistReason
	}

	if v >= FingerprintLogInfo {
		fields["is_mobile"] = f.IsMobile()
	}

	if v >= FingerprintLogVerbose {
		addVerboseFingerprintFields(fields, f)
	}

	return fields
}

// logFieldsReject builds the structured field set for a reject log. Only
// positive signals/flags are included; negative facts are dropped.
func (f *FingerprintData) logFieldsReject(clientIP, bouncerIP, reason string, v FingerprintLogVerbosity) log.Fields {
	fields := log.Fields{
		"reason":  reason,
		"signals": f.BotSignals(),
	}

	addCommonFingerprintFields(fields, f, clientIP, bouncerIP)

	if f.IsBot() {
		fields["is_bot"] = true
	}

	if f.Allowlisted {
		fields["allowlisted"] = true

		if f.AllowlistReason != "" {
			fields["allowlist_reason"] = f.AllowlistReason
		}
	}

	if v >= FingerprintLogInfo {
		if f.IsMobile() {
			fields["is_mobile"] = true
		}

		if f.HasAutomationSignal() {
			fields["automation"] = true
		}

		if f.HasHeadlessSignal() {
			fields["headless"] = true
		}

		if f.HasMismatchSignal() {
			fields["mismatch"] = true
		}

		if f.HasImpossibleDeviceSignal() {
			fields["impossible_device"] = true
		}
	}

	if v >= FingerprintLogVerbose {
		addVerboseFingerprintFields(fields, f)
	}

	return fields
}

// addCommonFingerprintFields adds the identity fields shared by accept
// and reject logs. Empty strings are omitted so partial / synthetic
// fingerprints (e.g. allowlist cookies with no measured signals) don't
// log noisy empty keys.
func addCommonFingerprintFields(fields log.Fields, f *FingerprintData, clientIP, bouncerIP string) {
	if clientIP != "" {
		fields["source"] = clientIP
	}

	if bouncerIP != "" {
		fields["bouncer"] = bouncerIP
	}

	if f.FSID != "" {
		fields["fsid"] = f.FSID
	}

	if ua := f.UserAgent(); ua != "" {
		fields["ua"] = ua
	}

	if p := f.Platform(); p != "" {
		fields["platform"] = p
	}
}

// addVerboseFingerprintFields adds the verbose-only fields shared by
// accept and reject logs. Zero / empty values are omitted.
func addVerboseFingerprintFields(fields log.Fields, f *FingerprintData) {
	if tz := f.Timezone(); tz != "" {
		fields["timezone"] = tz
	}

	if lang := f.Language(); lang != "" {
		fields["language"] = lang
	}

	if cpu := f.CPUCount(); cpu != 0 {
		fields["cpu_count"] = cpu
	}

	if mem := f.Memory(); mem != 0 {
		fields["memory"] = mem
	}

	if f.URL != "" {
		fields["url"] = f.URL
	}

	if f.Nonce != "" {
		fields["nonce"] = f.Nonce
	}

	if f.Time != 0 {
		fields["fp_time"] = f.Time
	}
}
