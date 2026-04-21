package challenge

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
