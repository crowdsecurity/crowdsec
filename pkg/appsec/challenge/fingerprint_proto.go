// fingerprint_proto.go bridges the protobuf-encoded fingerprint payload
// (pb.FingerprintData, the wire format used inside the encrypted cookie) and
// the FingerprintData struct used at runtime. Unexported helpers only; the
// conversion is mechanical field-by-field and intentionally verbose to keep
// it auditable. One helper per signal section, in the same order on both the
// from-proto and to-proto sides.

package challenge

import (
	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
)

func fingerprintDataFromProto(p *pb.FingerprintData) FingerprintData {
	f := FingerprintData{
		FSID:             p.GetFsid(),
		Nonce:            p.GetNonce(),
		Time:             p.GetTime(),
		URL:              p.GetUrl(),
		FastBotDetection: FlexBool(p.GetFastBotDetection()),
	}

	if s := p.GetSignals(); s != nil {
		f.Signals = signalsFromProto(s)
	}

	if det := p.GetFastBotDetectionDetails(); det != nil {
		f.FastBotDetectionDetails = fastBotDetectionDetailsFromProto(det)
	}

	f.Bot = newFingerprintBotAlias(f.FastBotDetectionDetails)

	return f
}

func signalsFromProto(s *pb.FingerprintSignals) fingerprintSignals {
	var out fingerprintSignals

	if a := s.GetAutomation(); a != nil {
		out.Automation = automationFromProto(a)
	}
	if d := s.GetDevice(); d != nil {
		out.Device = deviceFromProto(d)
	}
	if b := s.GetBrowser(); b != nil {
		out.Browser = browserFromProto(b)
	}
	if g := s.GetGraphics(); g != nil {
		out.Graphics = graphicsFromProto(g)
	}
	if c := s.GetCodecs(); c != nil {
		out.Codecs = codecsFromProto(c)
	}
	if l := s.GetLocale(); l != nil {
		out.Locale = localeFromProto(l)
	}
	if c := s.GetContexts(); c != nil {
		out.Contexts = contextsFromProto(c)
	}

	return out
}

func automationFromProto(a *pb.FingerprintAutomation) fingerprintAutomation {
	return fingerprintAutomation{
		Webdriver:                    FlexBool(a.GetWebdriver()),
		WebdriverWritable:            FlexBool(a.GetWebdriverWritable()),
		Selenium:                     FlexBool(a.GetSelenium()),
		CDP:                          FlexBool(a.GetCdp()),
		Playwright:                   FlexBool(a.GetPlaywright()),
		NavigatorPropertyDescriptors: a.GetNavigatorPropertyDescriptors(),
	}
}

func deviceFromProto(d *pb.FingerprintDevice) fingerprintDevice {
	out := fingerprintDevice{
		CPUCount: FlexInt(d.GetCpuCount()),
		Memory:   FlexInt(d.GetMemory()),
		Platform: d.GetPlatform(),
	}
	if sr := d.GetScreenResolution(); sr != nil {
		out.ScreenResolution = fingerprintScreenResolution{
			Width:               FlexInt(sr.GetWidth()),
			Height:              FlexInt(sr.GetHeight()),
			PixelDepth:          FlexInt(sr.GetPixelDepth()),
			ColorDepth:          FlexInt(sr.GetColorDepth()),
			AvailableWidth:      FlexInt(sr.GetAvailableWidth()),
			AvailableHeight:     FlexInt(sr.GetAvailableHeight()),
			InnerWidth:          FlexInt(sr.GetInnerWidth()),
			InnerHeight:         FlexInt(sr.GetInnerHeight()),
			HasMultipleDisplays: FlexBool(sr.GetHasMultipleDisplays()),
		}
	}
	if mm := d.GetMultimediaDevices(); mm != nil {
		out.MultimediaDevices = fingerprintMultimediaDevices{
			Speakers:    FlexInt(mm.GetSpeakers()),
			Microphones: FlexInt(mm.GetMicrophones()),
			Webcams:     FlexInt(mm.GetWebcams()),
		}
	}
	if mq := d.GetMediaQueries(); mq != nil {
		out.MediaQueries = fingerprintDeviceMediaQueries{
			PrefersColorScheme:         mq.GetPrefersColorScheme(),
			PrefersReducedMotion:       FlexBool(mq.GetPrefersReducedMotion()),
			PrefersReducedTransparency: FlexBool(mq.GetPrefersReducedTransparency()),
			ColorGamut:                 mq.GetColorGamut(),
			Pointer:                    mq.GetPointer(),
			AnyPointer:                 mq.GetAnyPointer(),
			Hover:                      FlexBool(mq.GetHover()),
			AnyHover:                   FlexBool(mq.GetAnyHover()),
			ColorDepth:                 FlexInt(mq.GetColorDepth()),
		}
	}

	return out
}

func browserFromProto(b *pb.FingerprintBrowser) fingerprintBrowser {
	out := fingerprintBrowser{
		UserAgent: b.GetUserAgent(),
		ETSL:      FlexInt(b.GetEtsl()),
		Maths:     b.GetMaths(),
	}
	if ft := b.GetFeatures(); ft != nil {
		out.Features = fingerprintBrowserFeatures{
			Bitmask:                   ft.GetBitmask(),
			Chrome:                    FlexBool(ft.GetChrome()),
			Brave:                     FlexBool(ft.GetBrave()),
			ApplePaySupport:           FlexBool(ft.GetApplePaySupport()),
			Opera:                     FlexBool(ft.GetOpera()),
			Serial:                    FlexBool(ft.GetSerial()),
			AttachShadow:              FlexBool(ft.GetAttachShadow()),
			Caches:                    FlexBool(ft.GetCaches()),
			WebAssembly:               FlexBool(ft.GetWebAssembly()),
			Buffer:                    FlexBool(ft.GetBuffer()),
			ShowModalDialog:           FlexBool(ft.GetShowModalDialog()),
			Safari:                    FlexBool(ft.GetSafari()),
			WebkitPrefixedFunction:    FlexBool(ft.GetWebkitPrefixedFunction()),
			MozPrefixedFunction:       FlexBool(ft.GetMozPrefixedFunction()),
			USB:                       FlexBool(ft.GetUsb()),
			BrowserCapture:            FlexBool(ft.GetBrowserCapture()),
			PaymentRequestUpdateEvent: FlexBool(ft.GetPaymentRequestUpdateEvent()),
			PressureObserver:          FlexBool(ft.GetPressureObserver()),
			AudioSession:              FlexBool(ft.GetAudioSession()),
			SelectAudioOutput:         FlexBool(ft.GetSelectAudioOutput()),
			BarcodeDetector:           FlexBool(ft.GetBarcodeDetector()),
			Battery:                   FlexBool(ft.GetBattery()),
			DevicePosture:             FlexBool(ft.GetDevicePosture()),
			DocumentPictureInPicture:  FlexBool(ft.GetDocumentPictureInPicture()),
			EyeDropper:                FlexBool(ft.GetEyeDropper()),
			EditContext:               FlexBool(ft.GetEditContext()),
			FencedFrame:               FlexBool(ft.GetFencedFrame()),
			Sanitizer:                 FlexBool(ft.GetSanitizer()),
			OTPCredential:             FlexBool(ft.GetOtpCredential()),
		}
	}
	if pl := b.GetPlugins(); pl != nil {
		out.Plugins = fingerprintBrowserPlugins{
			IsValidPluginArray: FlexBool(pl.GetIsValidPluginArray()),
			PluginCount:        FlexInt(pl.GetPluginCount()),
			PluginNamesHash:    pl.GetPluginNamesHash(),
			PluginConsistency1: FlexBool(pl.GetPluginConsistency1()),
			PluginOverflow:     FlexBool(pl.GetPluginOverflow()),
		}
	}
	if ext := b.GetExtensions(); ext != nil {
		out.Extensions = fingerprintBrowserExtensions{
			Bitmask:    ext.GetBitmask(),
			Extensions: ext.GetExtensions(),
		}
	}
	if hev := b.GetHighEntropyValues(); hev != nil {
		out.HighEntropyValues = fingerprintBrowserHighEntropyValues{
			Architecture:    hev.GetArchitecture(),
			Bitness:         hev.GetBitness(),
			Mobile:          FlexBool(hev.GetMobile()),
			Model:           hev.GetModel(),
			Platform:        hev.GetPlatform(),
			PlatformVersion: hev.GetPlatformVersion(),
			UAFullVersion:   hev.GetUaFullVersion(),
		}
		for _, bv := range hev.GetBrands() {
			out.HighEntropyValues.Brands = append(out.HighEntropyValues.Brands, fingerprintBrandVersion{
				Brand:   bv.GetBrand(),
				Version: bv.GetVersion(),
			})
		}
	}
	if tse := b.GetToSourceError(); tse != nil {
		out.ToSourceError = fingerprintBrowserToSourceError{
			ToSourceError: tse.GetToSourceError(),
			HasToSource:   FlexBool(tse.GetHasToSource()),
		}
	}

	return out
}

func graphicsFromProto(g *pb.FingerprintGraphics) fingerprintGraphics {
	var out fingerprintGraphics

	if gl := g.GetWebGL(); gl != nil {
		out.WebGL = fingerprintGraphicsWebGL{
			Vendor:   gl.GetVendor(),
			Renderer: gl.GetRenderer(),
		}
	}
	if gpu := g.GetWebgpu(); gpu != nil {
		out.WebGPU = fingerprintGraphicsWebGPU{
			Vendor:       gpu.GetVendor(),
			Architecture: gpu.GetArchitecture(),
			Device:       gpu.GetDevice(),
			Description:  gpu.GetDescription(),
		}
	}
	if cv := g.GetCanvas(); cv != nil {
		out.Canvas = fingerprintGraphicsCanvas{
			HasModifiedCanvas: FlexBool(cv.GetHasModifiedCanvas()),
			CanvasFingerprint: cv.GetCanvasFingerprint(),
		}
	}

	return out
}

func codecsFromProto(c *pb.FingerprintCodecs) fingerprintCodecs {
	return fingerprintCodecs{
		AudioCanPlayTypeHash:     c.GetAudioCanPlayTypeHash(),
		VideoCanPlayTypeHash:     c.GetVideoCanPlayTypeHash(),
		AudioMediaSourceHash:     c.GetAudioMediaSourceHash(),
		VideoMediaSourceHash:     c.GetVideoMediaSourceHash(),
		RTCAudioCapabilitiesHash: c.GetRtcAudioCapabilitiesHash(),
		RTCVideoCapabilitiesHash: c.GetRtcVideoCapabilitiesHash(),
		HasMediaSource:           FlexBool(c.GetHasMediaSource()),
	}
}

func localeFromProto(l *pb.FingerprintLocale) fingerprintLocale {
	var out fingerprintLocale

	if i18n := l.GetInternationalization(); i18n != nil {
		out.Internationalization = fingerprintLocaleInternationalization{
			Timezone:       i18n.GetTimezone(),
			LocaleLanguage: i18n.GetLocaleLanguage(),
		}
	}
	if lang := l.GetLanguages(); lang != nil {
		out.Languages = fingerprintLocaleLanguages{
			Languages: lang.GetLanguages(),
			Language:  lang.GetLanguage(),
		}
	}

	return out
}

func contextsFromProto(c *pb.FingerprintContexts) fingerprintContexts {
	var out fingerprintContexts

	if iframe := c.GetIframe(); iframe != nil {
		out.Iframe = fingerprintIframeContext{
			Webdriver: FlexBool(iframe.GetWebdriver()),
			UserAgent: iframe.GetUserAgent(),
			Platform:  iframe.GetPlatform(),
			Memory:    FlexInt(iframe.GetMemory()),
			CPUCount:  FlexInt(iframe.GetCpuCount()),
			Language:  iframe.GetLanguage(),
		}
	}
	if ww := c.GetWebWorker(); ww != nil {
		out.WebWorker = fingerprintWebWorkerContext{
			Vendor:    ww.GetVendor(),
			Renderer:  ww.GetRenderer(),
			UserAgent: ww.GetUserAgent(),
			Language:  ww.GetLanguage(),
			Platform:  ww.GetPlatform(),
			Memory:    FlexInt(ww.GetMemory()),
			CPUCount:  FlexInt(ww.GetCpuCount()),
		}
	}

	return out
}

func fastBotDetectionDetailsFromProto(det *pb.FingerprintFastBotDetectionDetails) fingerprintFastBotDetectionDetails {
	return fingerprintFastBotDetectionDetails{
		HeadlessChromeScreenResolution: fingerprintDetectionResult{Detected: FlexBool(det.GetHeadlessChromeScreenResolution().GetDetected())},
		HasWebdriver:                   fingerprintDetectionResult{Detected: FlexBool(det.GetHasWebdriver().GetDetected())},
		HasWebdriverWritable:           fingerprintDetectionResult{Detected: FlexBool(det.GetHasWebdriverWritable().GetDetected())},
		HasSeleniumProperty:            fingerprintDetectionResult{Detected: FlexBool(det.GetHasSeleniumProperty().GetDetected())},
		HasCDP:                         fingerprintDetectionResult{Detected: FlexBool(det.GetHasCDP().GetDetected())},
		HasPlaywright:                  fingerprintDetectionResult{Detected: FlexBool(det.GetHasPlaywright().GetDetected())},
		HasImpossibleDeviceMemory:      fingerprintDetectionResult{Detected: FlexBool(det.GetHasImpossibleDeviceMemory().GetDetected())},
		HasHighCPUCount:                fingerprintDetectionResult{Detected: FlexBool(det.GetHasHighCPUCount().GetDetected())},
		HasMissingChromeObject:         fingerprintDetectionResult{Detected: FlexBool(det.GetHasMissingChromeObject().GetDetected())},
		HasWebdriverIframe:             fingerprintDetectionResult{Detected: FlexBool(det.GetHasWebdriverIframe().GetDetected())},
		HasWebdriverWorker:             fingerprintDetectionResult{Detected: FlexBool(det.GetHasWebdriverWorker().GetDetected())},
		HasMismatchWebGLInWorker:       fingerprintDetectionResult{Detected: FlexBool(det.GetHasMismatchWebGLInWorker().GetDetected())},
		HasMismatchPlatformIframe:      fingerprintDetectionResult{Detected: FlexBool(det.GetHasMismatchPlatformIframe().GetDetected())},
		HasMismatchPlatformWorker:      fingerprintDetectionResult{Detected: FlexBool(det.GetHasMismatchPlatformWorker().GetDetected())},
		HasSwiftshaderRenderer:         fingerprintDetectionResult{Detected: FlexBool(det.GetHasSwiftshaderRenderer().GetDetected())},
		HasUTCTimezone:                 fingerprintDetectionResult{Detected: FlexBool(det.GetHasUTCTimezone().GetDetected())},
		HasMismatchLanguages:           fingerprintDetectionResult{Detected: FlexBool(det.GetHasMismatchLanguages().GetDetected())},
		HasInconsistentEtsl:            fingerprintDetectionResult{Detected: FlexBool(det.GetHasInconsistentEtsl().GetDetected())},
		HasBotUserAgent:                fingerprintDetectionResult{Detected: FlexBool(det.GetHasBotUserAgent().GetDetected())},
		HasGPUMismatch:                 fingerprintDetectionResult{Detected: FlexBool(det.GetHasGPUMismatch().GetDetected())},
		HasPlatformMismatch:            fingerprintDetectionResult{Detected: FlexBool(det.GetHasPlatformMismatch().GetDetected())},
	}
}

func (f *FingerprintData) ToProto() *pb.FingerprintData {
	return &pb.FingerprintData{
		Signals: &pb.FingerprintSignals{
			Automation: f.Signals.Automation.toProto(),
			Device:     f.Signals.Device.toProto(),
			Browser:    f.Signals.Browser.toProto(),
			Graphics:   f.Signals.Graphics.toProto(),
			Codecs:     f.Signals.Codecs.toProto(),
			Locale:     f.Signals.Locale.toProto(),
			Contexts:   f.Signals.Contexts.toProto(),
		},
		Fsid:                    f.FSID,
		Nonce:                   f.Nonce,
		Time:                    f.Time,
		Url:                     f.URL,
		FastBotDetection:        bool(f.FastBotDetection),
		FastBotDetectionDetails: f.FastBotDetectionDetails.toProto(),
		Bot:                     f.Bot.toProto(),
	}
}

func (a fingerprintAutomation) toProto() *pb.FingerprintAutomation {
	return &pb.FingerprintAutomation{
		Webdriver:                    bool(a.Webdriver),
		WebdriverWritable:            bool(a.WebdriverWritable),
		Selenium:                     bool(a.Selenium),
		Cdp:                          bool(a.CDP),
		Playwright:                   bool(a.Playwright),
		NavigatorPropertyDescriptors: a.NavigatorPropertyDescriptors,
	}
}

func (d fingerprintDevice) toProto() *pb.FingerprintDevice {
	return &pb.FingerprintDevice{
		CpuCount: int32(d.CPUCount),
		Memory:   int32(d.Memory),
		Platform: d.Platform,
		ScreenResolution: &pb.FingerprintScreenResolution{
			Width:               int32(d.ScreenResolution.Width),
			Height:              int32(d.ScreenResolution.Height),
			PixelDepth:          int32(d.ScreenResolution.PixelDepth),
			ColorDepth:          int32(d.ScreenResolution.ColorDepth),
			AvailableWidth:      int32(d.ScreenResolution.AvailableWidth),
			AvailableHeight:     int32(d.ScreenResolution.AvailableHeight),
			InnerWidth:          int32(d.ScreenResolution.InnerWidth),
			InnerHeight:         int32(d.ScreenResolution.InnerHeight),
			HasMultipleDisplays: bool(d.ScreenResolution.HasMultipleDisplays),
		},
		MultimediaDevices: &pb.FingerprintMultimediaDevices{
			Speakers:    int32(d.MultimediaDevices.Speakers),
			Microphones: int32(d.MultimediaDevices.Microphones),
			Webcams:     int32(d.MultimediaDevices.Webcams),
		},
		MediaQueries: &pb.FingerprintDeviceMediaQueries{
			PrefersColorScheme:         d.MediaQueries.PrefersColorScheme,
			PrefersReducedMotion:       bool(d.MediaQueries.PrefersReducedMotion),
			PrefersReducedTransparency: bool(d.MediaQueries.PrefersReducedTransparency),
			ColorGamut:                 d.MediaQueries.ColorGamut,
			Pointer:                    d.MediaQueries.Pointer,
			AnyPointer:                 d.MediaQueries.AnyPointer,
			Hover:                      bool(d.MediaQueries.Hover),
			AnyHover:                   bool(d.MediaQueries.AnyHover),
			ColorDepth:                 int32(d.MediaQueries.ColorDepth),
		},
	}
}

func (b fingerprintBrowser) toProto() *pb.FingerprintBrowser {
	brands := make([]*pb.FingerprintBrandVersion, len(b.HighEntropyValues.Brands))
	for i, bv := range b.HighEntropyValues.Brands {
		brands[i] = &pb.FingerprintBrandVersion{
			Brand:   bv.Brand,
			Version: bv.Version,
		}
	}

	return &pb.FingerprintBrowser{
		UserAgent: b.UserAgent,
		Features: &pb.FingerprintBrowserFeatures{
			Bitmask:                   b.Features.Bitmask,
			Chrome:                    bool(b.Features.Chrome),
			Brave:                     bool(b.Features.Brave),
			ApplePaySupport:           bool(b.Features.ApplePaySupport),
			Opera:                     bool(b.Features.Opera),
			Serial:                    bool(b.Features.Serial),
			AttachShadow:              bool(b.Features.AttachShadow),
			Caches:                    bool(b.Features.Caches),
			WebAssembly:               bool(b.Features.WebAssembly),
			Buffer:                    bool(b.Features.Buffer),
			ShowModalDialog:           bool(b.Features.ShowModalDialog),
			Safari:                    bool(b.Features.Safari),
			WebkitPrefixedFunction:    bool(b.Features.WebkitPrefixedFunction),
			MozPrefixedFunction:       bool(b.Features.MozPrefixedFunction),
			Usb:                       bool(b.Features.USB),
			BrowserCapture:            bool(b.Features.BrowserCapture),
			PaymentRequestUpdateEvent: bool(b.Features.PaymentRequestUpdateEvent),
			PressureObserver:          bool(b.Features.PressureObserver),
			AudioSession:              bool(b.Features.AudioSession),
			SelectAudioOutput:         bool(b.Features.SelectAudioOutput),
			BarcodeDetector:           bool(b.Features.BarcodeDetector),
			Battery:                   bool(b.Features.Battery),
			DevicePosture:             bool(b.Features.DevicePosture),
			DocumentPictureInPicture:  bool(b.Features.DocumentPictureInPicture),
			EyeDropper:                bool(b.Features.EyeDropper),
			EditContext:               bool(b.Features.EditContext),
			FencedFrame:               bool(b.Features.FencedFrame),
			Sanitizer:                 bool(b.Features.Sanitizer),
			OtpCredential:             bool(b.Features.OTPCredential),
		},
		Plugins: &pb.FingerprintBrowserPlugins{
			IsValidPluginArray: bool(b.Plugins.IsValidPluginArray),
			PluginCount:        int32(b.Plugins.PluginCount),
			PluginNamesHash:    b.Plugins.PluginNamesHash,
			PluginConsistency1: bool(b.Plugins.PluginConsistency1),
			PluginOverflow:     bool(b.Plugins.PluginOverflow),
		},
		Extensions: &pb.FingerprintBrowserExtensions{
			Bitmask:    b.Extensions.Bitmask,
			Extensions: b.Extensions.Extensions,
		},
		HighEntropyValues: &pb.FingerprintBrowserHighEntropyValues{
			Architecture:    b.HighEntropyValues.Architecture,
			Bitness:         b.HighEntropyValues.Bitness,
			Brands:          brands,
			Mobile:          bool(b.HighEntropyValues.Mobile),
			Model:           b.HighEntropyValues.Model,
			Platform:        b.HighEntropyValues.Platform,
			PlatformVersion: b.HighEntropyValues.PlatformVersion,
			UaFullVersion:   b.HighEntropyValues.UAFullVersion,
		},
		Etsl:  int32(b.ETSL),
		Maths: b.Maths,
		ToSourceError: &pb.FingerprintBrowserToSourceError{
			ToSourceError: b.ToSourceError.ToSourceError,
			HasToSource:   bool(b.ToSourceError.HasToSource),
		},
	}
}

func (g fingerprintGraphics) toProto() *pb.FingerprintGraphics {
	return &pb.FingerprintGraphics{
		WebGL: &pb.FingerprintGraphicsWebGL{
			Vendor:   g.WebGL.Vendor,
			Renderer: g.WebGL.Renderer,
		},
		Webgpu: &pb.FingerprintGraphicsWebGPU{
			Vendor:       g.WebGPU.Vendor,
			Architecture: g.WebGPU.Architecture,
			Device:       g.WebGPU.Device,
			Description:  g.WebGPU.Description,
		},
		Canvas: &pb.FingerprintGraphicsCanvas{
			HasModifiedCanvas: bool(g.Canvas.HasModifiedCanvas),
			CanvasFingerprint: g.Canvas.CanvasFingerprint,
		},
	}
}

func (c fingerprintCodecs) toProto() *pb.FingerprintCodecs {
	return &pb.FingerprintCodecs{
		AudioCanPlayTypeHash:     c.AudioCanPlayTypeHash,
		VideoCanPlayTypeHash:     c.VideoCanPlayTypeHash,
		AudioMediaSourceHash:     c.AudioMediaSourceHash,
		VideoMediaSourceHash:     c.VideoMediaSourceHash,
		RtcAudioCapabilitiesHash: c.RTCAudioCapabilitiesHash,
		RtcVideoCapabilitiesHash: c.RTCVideoCapabilitiesHash,
		HasMediaSource:           bool(c.HasMediaSource),
	}
}

func (l fingerprintLocale) toProto() *pb.FingerprintLocale {
	return &pb.FingerprintLocale{
		Internationalization: &pb.FingerprintLocaleInternationalization{
			Timezone:       l.Internationalization.Timezone,
			LocaleLanguage: l.Internationalization.LocaleLanguage,
		},
		Languages: &pb.FingerprintLocaleLanguages{
			Languages: l.Languages.Languages,
			Language:  l.Languages.Language,
		},
	}
}

func (c fingerprintContexts) toProto() *pb.FingerprintContexts {
	return &pb.FingerprintContexts{
		Iframe: &pb.FingerprintIframeContext{
			Webdriver: bool(c.Iframe.Webdriver),
			UserAgent: c.Iframe.UserAgent,
			Platform:  c.Iframe.Platform,
			Memory:    int32(c.Iframe.Memory),
			CpuCount:  int32(c.Iframe.CPUCount),
			Language:  c.Iframe.Language,
		},
		WebWorker: &pb.FingerprintWebWorkerContext{
			Vendor:    c.WebWorker.Vendor,
			Renderer:  c.WebWorker.Renderer,
			UserAgent: c.WebWorker.UserAgent,
			Language:  c.WebWorker.Language,
			Platform:  c.WebWorker.Platform,
			Memory:    int32(c.WebWorker.Memory),
			CpuCount:  int32(c.WebWorker.CPUCount),
		},
	}
}

func (d fingerprintFastBotDetectionDetails) toProto() *pb.FingerprintFastBotDetectionDetails {
	return &pb.FingerprintFastBotDetectionDetails{
		HeadlessChromeScreenResolution: &pb.FingerprintDetectionResult{Detected: bool(d.HeadlessChromeScreenResolution.Detected)},
		HasWebdriver:                   &pb.FingerprintDetectionResult{Detected: bool(d.HasWebdriver.Detected)},
		HasWebdriverWritable:           &pb.FingerprintDetectionResult{Detected: bool(d.HasWebdriverWritable.Detected)},
		HasSeleniumProperty:            &pb.FingerprintDetectionResult{Detected: bool(d.HasSeleniumProperty.Detected)},
		HasCDP:                         &pb.FingerprintDetectionResult{Detected: bool(d.HasCDP.Detected)},
		HasPlaywright:                  &pb.FingerprintDetectionResult{Detected: bool(d.HasPlaywright.Detected)},
		HasImpossibleDeviceMemory:      &pb.FingerprintDetectionResult{Detected: bool(d.HasImpossibleDeviceMemory.Detected)},
		HasHighCPUCount:                &pb.FingerprintDetectionResult{Detected: bool(d.HasHighCPUCount.Detected)},
		HasMissingChromeObject:         &pb.FingerprintDetectionResult{Detected: bool(d.HasMissingChromeObject.Detected)},
		HasWebdriverIframe:             &pb.FingerprintDetectionResult{Detected: bool(d.HasWebdriverIframe.Detected)},
		HasWebdriverWorker:             &pb.FingerprintDetectionResult{Detected: bool(d.HasWebdriverWorker.Detected)},
		HasMismatchWebGLInWorker:       &pb.FingerprintDetectionResult{Detected: bool(d.HasMismatchWebGLInWorker.Detected)},
		HasMismatchPlatformIframe:      &pb.FingerprintDetectionResult{Detected: bool(d.HasMismatchPlatformIframe.Detected)},
		HasMismatchPlatformWorker:      &pb.FingerprintDetectionResult{Detected: bool(d.HasMismatchPlatformWorker.Detected)},
		HasSwiftshaderRenderer:         &pb.FingerprintDetectionResult{Detected: bool(d.HasSwiftshaderRenderer.Detected)},
		HasUTCTimezone:                 &pb.FingerprintDetectionResult{Detected: bool(d.HasUTCTimezone.Detected)},
		HasMismatchLanguages:           &pb.FingerprintDetectionResult{Detected: bool(d.HasMismatchLanguages.Detected)},
		HasInconsistentEtsl:            &pb.FingerprintDetectionResult{Detected: bool(d.HasInconsistentEtsl.Detected)},
		HasBotUserAgent:                &pb.FingerprintDetectionResult{Detected: bool(d.HasBotUserAgent.Detected)},
		HasGPUMismatch:                 &pb.FingerprintDetectionResult{Detected: bool(d.HasGPUMismatch.Detected)},
		HasPlatformMismatch:            &pb.FingerprintDetectionResult{Detected: bool(d.HasPlatformMismatch.Detected)},
	}
}

func (b fingerprintBotAlias) toProto() *pb.FingerprintBotAlias {
	return &pb.FingerprintBotAlias{
		HeadlessChromeScreenResolution: b.HeadlessChromeScreenResolution,
		Webdriver:                      b.Webdriver,
		WebdriverWritable:              b.WebdriverWritable,
		Selenium:                       b.Selenium,
		Cdp:                            b.CDP,
		Playwright:                     b.Playwright,
		ImpossibleDeviceMemory:         b.ImpossibleDeviceMemory,
		HighCPUCount:                   b.HighCPUCount,
		MissingChromeObject:            b.MissingChromeObject,
		WebdriverIframe:                b.WebdriverIframe,
		WebdriverWorker:                b.WebdriverWorker,
		MismatchWebGLInWorker:          b.MismatchWebGLInWorker,
		MismatchPlatformIframe:         b.MismatchPlatformIframe,
		MismatchPlatformWorker:         b.MismatchPlatformWorker,
		SwiftshaderRenderer:            b.SwiftshaderRenderer,
		UtcTimezone:                    b.UTCTimezone,
		MismatchLanguages:              b.MismatchLanguages,
		InconsistentEtsl:               b.InconsistentEtsl,
		BotUserAgent:                   b.BotUserAgent,
		GpuMismatch:                    b.GPUMismatch,
		PlatformMismatch:               b.PlatformMismatch,
		AnyDetected:                    b.AnyDetected,
		DetectedCount:                  int32(b.DetectedCount),
	}
}
