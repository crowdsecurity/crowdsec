// Package fsid decodes an FSID (the JA4-inspired fingerprint id produced by
// fpscanner's generateFingerprintScannerId) back into a fingerprint object.
//
// Only the fields the FSID actually encodes can be recovered: bitmasks, screen
// geometry, cpu/memory, language and timezone. Everything else was folded into
// truncated hashes and is gone; those fields are simply left out of the object.
//
// Stdlib only on purpose: no crowdsec imports, so it stays usable from
// anywhere (cscli, tests, standalone tooling).
package fsid

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Bit orders below must stay in sync with generateFingerprintScannerId() in
// pkg/appsec/challenge/js/fpscanner/fpscanner/src/index.ts.

type detection struct {
	name     string
	severity string
}

var detectionBits = []detection{
	{"headlessChromeScreenResolution", "high"},
	{"hasWebdriver", "high"},
	{"hasWebdriverWritable", "high"},
	{"hasSeleniumProperty", "high"},
	{"hasCDP", "high"},
	{"hasPlaywright", "high"},
	{"hasImpossibleDeviceMemory", "high"},
	{"hasHighCPUCount", "high"},
	{"hasMissingChromeObject", "high"},
	{"hasWebdriverIframe", "high"},
	{"hasWebdriverWorker", "high"},
	{"hasMismatchWebGLInWorker", "high"},
	{"hasMismatchPlatformIframe", "high"},
	{"hasMismatchPlatformWorker", "high"},
	{"hasSwiftshaderRenderer", "low"},
	{"hasUTCTimezone", "medium"},
	{"hasMismatchLanguages", "low"},
	{"hasInconsistentEtsl", "high"},
	{"hasBotUserAgent", "high"},
	{"hasGPUMismatch", "high"},
	{"hasPlatformMismatch", "high"},
}

var automationBits = []string{"webdriver", "webdriverWritable", "selenium", "cdp", "playwright"}

var deviceBits = []string{
	"screenResolution.hasMultipleDisplays",
	"mediaQueries.prefersReducedMotion",
	"mediaQueries.prefersReducedTransparency",
	"mediaQueries.hover",
	"mediaQueries.anyHover",
}

var featureBits = []string{
	"chrome", "brave", "applePaySupport", "opera", "serial", "attachShadow", "caches",
	"webAssembly", "buffer", "showModalDialog", "safari", "webkitPrefixedFunction",
	"mozPrefixedFunction", "usb", "browserCapture", "paymentRequestUpdateEvent",
	"pressureObserver", "audioSession", "selectAudioOutput", "barcodeDetector", "battery",
	"devicePosture", "documentPictureInPicture", "eyeDropper", "editContext", "fencedFrame",
	"sanitizer", "otpCredential", "sumPrecise",
}

var extensionBits = []string{
	"grammarly", "metamask", "coupon-birds", "deepl", "monica-ai", "sider-ai", "requestly", "veepn",
}

var pluginBits = []string{
	"plugins.isValidPluginArray",
	"plugins.pluginConsistency1",
	"plugins.pluginOverflow",
	"toSourceError.hasToSource",
}

var contextBits = []string{
	"mismatch.iframe",
	"mismatch.worker",
	"iframe.webdriver",
	"webWorker.webdriver",
}

// Hashes are hashCode() output: hex, possibly with a leading '-', truncated.
const hashRe = `(-?[0-9a-f]*)`

var (
	autoRe      = regexp.MustCompile(`^([01]*)h` + hashRe + `$`)
	devRe       = regexp.MustCompile(`^(\d+)x(\d+)c(\d+)m(\d+)b([01]*)h` + hashRe + `$`)
	brwRe       = regexp.MustCompile(`^f([01]*)e([01]*)p([01]*)h` + hashRe + `$`)
	maskHashRe  = regexp.MustCompile(`^([01]*)h` + hashRe + `$`)
	locRe       = regexp.MustCompile(`^([a-z]{2})(\d+)t(.*)_h` + hashRe + `$`)
	locLegacyRe = regexp.MustCompile(`^([a-z]{2})(\d+)h` + hashRe + `$`)
)

type FSID struct {
	Raw     string
	Version string

	Detections map[string]bool
	Automation map[string]bool

	Width, Height int
	CPUCount      int
	Memory        int
	Device        map[string]bool

	Features   map[string]bool
	Extensions map[string]bool
	Plugins    map[string]bool

	ModifiedCanvas bool
	HasMediaSource bool

	Language  string
	LangCount int
	Timezone  string

	Contexts map[string]bool

	// Hashes of the signals the FSID does not carry in clear.
	Hashes map[string]string
	// Sections kept verbatim, handy when a section fails to match.
	Sections map[string]string
	Warnings []string
}

func bits(mask string, names []string) map[string]bool {
	out := make(map[string]bool, len(names))

	for i, name := range names {
		if i < len(mask) {
			out[name] = mask[i] == '1'
		}
	}

	return out
}

// Parse decodes an FSID string. Sections that fail to decode are reported in
// Warnings rather than as an error: a partially readable FSID is still useful.
func Parse(raw string) (*FSID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty fsid")
	}

	parts := strings.Split(raw, "_")
	if len(parts) < 9 {
		return nil, fmt.Errorf("expected at least 9 '_'-separated sections, got %d (%q)", len(parts), raw)
	}

	f := &FSID{
		Raw:      raw,
		Version:  parts[0],
		Hashes:   map[string]string{},
		Sections: map[string]string{},
	}

	if f.Version != "FS1" {
		f.warnf("unknown version %q, decoding as FS1", f.Version)
	}

	// The locale section embeds a sanitized timezone which may itself contain
	// '_' (America/New_York -> America-New_York), so anchor on both ends:
	// fixed sections from the left, contexts last, locale is what remains.
	det, auto, dev, brw, gfx, cod := parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
	ctx := parts[len(parts)-1]
	loc := strings.Join(parts[7:len(parts)-1], "_")

	f.Sections = map[string]string{
		"det": det, "auto": auto, "dev": dev, "brw": brw,
		"gfx": gfx, "cod": cod, "loc": loc, "ctx": ctx,
	}

	if len(det) != len(detectionBits) {
		f.warnf("detection bitmask is %d bits, this build knows %d (bundle version mismatch?)", len(det), len(detectionBits))
	}

	f.Detections = bits(det, detectionBits2names())

	if m := autoRe.FindStringSubmatch(auto); m != nil {
		f.Automation = bits(m[1], automationBits)
		f.Hashes["navigatorPropertyDescriptors"] = m[2]
	} else {
		f.warnf("cannot parse automation section %q", auto)
	}

	if m := devRe.FindStringSubmatch(dev); m != nil {
		f.Width, _ = strconv.Atoi(m[1])
		f.Height, _ = strconv.Atoi(m[2])
		f.CPUCount, _ = strconv.Atoi(m[3])
		f.Memory, _ = strconv.Atoi(m[4])
		f.Device = bits(m[5], deviceBits)
		f.Hashes["device"] = m[6]
	} else {
		f.warnf("cannot parse device section %q", dev)
	}

	if m := brwRe.FindStringSubmatch(brw); m != nil {
		f.Features = bits(m[1], featureBits)
		f.Extensions = bits(m[2], extensionBits)
		f.Plugins = bits(m[3], pluginBits)
		f.Hashes["browser"] = m[4]

		if len(m[1]) != len(featureBits) {
			f.warnf("features bitmask is %d bits, this build knows %d", len(m[1]), len(featureBits))
		}
	} else {
		f.warnf("cannot parse browser section %q", brw)
	}

	if m := maskHashRe.FindStringSubmatch(gfx); m != nil {
		f.ModifiedCanvas = strings.HasPrefix(m[1], "1")
		f.Hashes["graphics"] = m[2]
	} else {
		f.warnf("cannot parse graphics section %q", gfx)
	}

	if m := maskHashRe.FindStringSubmatch(cod); m != nil {
		f.HasMediaSource = strings.HasPrefix(m[1], "1")
		f.Hashes["codecs"] = m[2]
	} else {
		f.warnf("cannot parse codecs section %q", cod)
	}

	switch m := locRe.FindStringSubmatch(loc); {
	case m != nil:
		f.Language = m[1]
		f.LangCount, _ = strconv.Atoi(m[2])
		f.Timezone = m[3]
		f.Hashes["locale"] = m[4]
	default:
		if m := locLegacyRe.FindStringSubmatch(loc); m != nil {
			f.Language = m[1]
			f.LangCount, _ = strconv.Atoi(m[2])
			f.Hashes["locale"] = m[3]
			f.warnf("locale section has no timezone (pre-timezone bundle)")
		} else {
			f.warnf("cannot parse locale section %q", loc)
		}
	}

	if m := maskHashRe.FindStringSubmatch(ctx); m != nil {
		f.Contexts = bits(m[1], contextBits)
		f.Hashes["contexts"] = m[2]
	} else {
		f.warnf("cannot parse contexts section %q", ctx)
	}

	return f, nil
}

func detectionBits2names() []string {
	names := make([]string, 0, len(detectionBits))
	for _, d := range detectionBits {
		names = append(names, d.name)
	}

	return names
}

func (f *FSID) warnf(format string, args ...any) {
	f.Warnings = append(f.Warnings, fmt.Sprintf(format, args...))
}

// Fingerprint rebuilds the JSON wire shape consumed by
// challenge.FingerprintData, with only the fields the FSID encodes.
func (f *FSID) Fingerprint() map[string]any {
	details := map[string]any{}
	anyDetected := false

	for _, d := range detectionBits {
		detected := f.Detections[d.name]
		anyDetected = anyDetected || detected
		details[d.name] = map[string]any{"detected": detected, "severity": d.severity}
	}

	automation := map[string]any{}
	for _, name := range automationBits {
		automation[name] = f.Automation[name]
	}

	features := map[string]any{"bitmask": strings.TrimPrefix(f.Sections["brw"], "f")}
	for _, name := range featureBits {
		features[name] = f.Features[name]
	}
	// keep only the real bitmask, not the whole section
	if m := brwRe.FindStringSubmatch(f.Sections["brw"]); m != nil {
		features["bitmask"] = m[1]
	}

	extNames := []string{}
	extMask := strings.Builder{}

	for _, name := range extensionBits {
		if f.Extensions[name] {
			extNames = append(extNames, name)
			extMask.WriteByte('1')
		} else {
			extMask.WriteByte('0')
		}
	}

	fp := map[string]any{
		"fsid":                    f.Raw,
		"fastBotDetection":        anyDetected,
		"fastBotDetectionDetails": details,
		"signals": map[string]any{
			"automation": automation,
			"device": map[string]any{
				"cpuCount": f.CPUCount,
				"memory":   f.Memory,
				"screenResolution": map[string]any{
					"width":               f.Width,
					"height":              f.Height,
					"hasMultipleDisplays": f.Device["screenResolution.hasMultipleDisplays"],
				},
				"mediaQueries": map[string]any{
					"prefersReducedMotion":       f.Device["mediaQueries.prefersReducedMotion"],
					"prefersReducedTransparency": f.Device["mediaQueries.prefersReducedTransparency"],
					"hover":                      f.Device["mediaQueries.hover"],
					"anyHover":                   f.Device["mediaQueries.anyHover"],
				},
			},
			"browser": map[string]any{
				"features": features,
				"extensions": map[string]any{
					"bitmask":    extMask.String(),
					"extensions": extNames,
				},
				"plugins": map[string]any{
					"isValidPluginArray": f.Plugins["plugins.isValidPluginArray"],
					"pluginConsistency1": f.Plugins["plugins.pluginConsistency1"],
					"pluginOverflow":     f.Plugins["plugins.pluginOverflow"],
				},
				"toSourceError": map[string]any{
					"hasToSource": f.Plugins["toSourceError.hasToSource"],
				},
			},
			"graphics": map[string]any{
				"canvas": map[string]any{"hasModifiedCanvas": f.ModifiedCanvas},
			},
			"codecs": map[string]any{"hasMediaSource": f.HasMediaSource},
			"locale": map[string]any{
				"internationalization": map[string]any{"timezone": f.Timezone},
				"languages":            map[string]any{"language": f.Language},
			},
			"contexts": map[string]any{
				"iframe":    map[string]any{"webdriver": f.Contexts["iframe.webdriver"]},
				"webWorker": map[string]any{"webdriver": f.Contexts["webWorker.webdriver"]},
			},
		},
		// Not part of the wire shape: what the FSID says but the object cannot hold.
		"_fsid": map[string]any{
			"version":             f.Version,
			"sections":            f.Sections,
			"lostSignalHashes":    f.Hashes,
			"languageCount":       f.LangCount,
			"contextMismatch":     map[string]any{"iframe": f.Contexts["mismatch.iframe"], "worker": f.Contexts["mismatch.worker"]},
			"languageIsTruncated": true,
			"warnings":            f.Warnings,
		},
	}

	return fp
}

func setNames(m map[string]bool, order []string) []string {
	out := []string{}

	for _, name := range order {
		if m[name] {
			out = append(out, name)
		}
	}

	return out
}

// WriteHuman renders a readable summary of what the FSID carries.
func (f *FSID) WriteHuman(w io.Writer) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }

	p("fsid      %s", f.Raw)
	p("version   %s", f.Version)

	for _, warn := range f.Warnings {
		p("warning   %s", warn)
	}

	p("")

	detected := setNames(f.Detections, detectionBits2names())
	if len(detected) == 0 {
		p("detections   none")
	} else {
		p("detections   %d triggered", len(detected))

		for _, name := range detected {
			sev := "?"

			for _, d := range detectionBits {
				if d.name == name {
					sev = d.severity
				}
			}

			p("             %-32s %s", name, sev)
		}
	}

	p("")
	p("automation   %s", orNone(setNames(f.Automation, automationBits)))
	p("")
	p("screen       %dx%d", f.Width, f.Height)
	p("cpu/mem      %d cores / %d GB", f.CPUCount, f.Memory)
	p("device       %s", orNone(setNames(f.Device, deviceBits)))
	p("")
	p("features     %s", orNone(setNames(f.Features, featureBits)))
	p("extensions   %s", orNone(setNames(f.Extensions, extensionBits)))
	p("plugins      %s", orNone(setNames(f.Plugins, pluginBits)))
	p("")
	p("canvas       modified=%t", f.ModifiedCanvas)
	p("codecs       mediaSource=%t", f.HasMediaSource)
	p("")
	p("language     %s (truncated to 2 chars) / %d languages", f.Language, f.LangCount)
	p("timezone     %s", orUnknown(f.Timezone))
	p("")
	p("contexts     %s", orNone(setNames(f.Contexts, contextBits)))
	p("")
	p("hashes (signals not recoverable from the fsid)")

	for _, name := range []string{"navigatorPropertyDescriptors", "device", "browser", "graphics", "codecs", "locale", "contexts"} {
		if h, ok := f.Hashes[name]; ok {
			p("             %-30s %s", name, h)
		}
	}
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "none"
	}

	return strings.Join(v, ", ")
}

func orUnknown(v string) string {
	if v == "" {
		return "(not encoded)"
	}

	return v
}
