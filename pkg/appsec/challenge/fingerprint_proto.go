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
		if a := s.GetAutomation(); a != nil {
			f.Signals.Automation = fingerprintAutomation{
				Webdriver:                    FlexBool(a.GetWebdriver()),
				WebdriverWritable:            FlexBool(a.GetWebdriverWritable()),
				Selenium:                     FlexBool(a.GetSelenium()),
				CDP:                          FlexBool(a.GetCdp()),
				Playwright:                   FlexBool(a.GetPlaywright()),
				NavigatorPropertyDescriptors: a.GetNavigatorPropertyDescriptors(),
			}
		}

		if d := s.GetDevice(); d != nil {
			f.Signals.Device = fingerprintDevice{
				CPUCount: FlexInt(d.GetCpuCount()),
				Memory:   FlexInt(d.GetMemory()),
				Platform: d.GetPlatform(),
			}
			if sr := d.GetScreenResolution(); sr != nil {
				f.Signals.Device.ScreenResolution = fingerprintScreenResolution{
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
				f.Signals.Device.MultimediaDevices = fingerprintMultimediaDevices{
					Speakers:    FlexInt(mm.GetSpeakers()),
					Microphones: FlexInt(mm.GetMicrophones()),
					Webcams:     FlexInt(mm.GetWebcams()),
				}
			}
			if mq := d.GetMediaQueries(); mq != nil {
				f.Signals.Device.MediaQueries = fingerprintDeviceMediaQueries{
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
		}

		if b := s.GetBrowser(); b != nil {
			f.Signals.Browser = fingerprintBrowser{
				UserAgent: b.GetUserAgent(),
				ETSL:      FlexInt(b.GetEtsl()),
				Maths:     b.GetMaths(),
			}
			if ft := b.GetFeatures(); ft != nil {
				f.Signals.Browser.Features = fingerprintBrowserFeatures{
					Bitmask:         ft.GetBitmask(),
					Chrome:          FlexBool(ft.GetChrome()),
					Brave:           FlexBool(ft.GetBrave()),
					ApplePaySupport: FlexBool(ft.GetApplePaySupport()),
					Opera:           FlexBool(ft.GetOpera()),
					Serial:          FlexBool(ft.GetSerial()),
					AttachShadow:    FlexBool(ft.GetAttachShadow()),
					Caches:          FlexBool(ft.GetCaches()),
					WebAssembly:     FlexBool(ft.GetWebAssembly()),
					Buffer:          FlexBool(ft.GetBuffer()),
					ShowModalDialog: FlexBool(ft.GetShowModalDialog()),
				}
			}
			if pl := b.GetPlugins(); pl != nil {
				f.Signals.Browser.Plugins = fingerprintBrowserPlugins{
					IsValidPluginArray: FlexBool(pl.GetIsValidPluginArray()),
					PluginCount:        FlexInt(pl.GetPluginCount()),
					PluginNamesHash:    pl.GetPluginNamesHash(),
					PluginConsistency1: FlexBool(pl.GetPluginConsistency1()),
					PluginOverflow:     FlexBool(pl.GetPluginOverflow()),
				}
			}
			if ext := b.GetExtensions(); ext != nil {
				f.Signals.Browser.Extensions = fingerprintBrowserExtensions{
					Bitmask:    ext.GetBitmask(),
					Extensions: ext.GetExtensions(),
				}
			}
			if hev := b.GetHighEntropyValues(); hev != nil {
				f.Signals.Browser.HighEntropyValues = fingerprintBrowserHighEntropyValues{
					Architecture:    hev.GetArchitecture(),
					Bitness:         hev.GetBitness(),
					Mobile:          FlexBool(hev.GetMobile()),
					Model:           hev.GetModel(),
					Platform:        hev.GetPlatform(),
					PlatformVersion: hev.GetPlatformVersion(),
					UAFullVersion:   hev.GetUaFullVersion(),
				}
				for _, bv := range hev.GetBrands() {
					f.Signals.Browser.HighEntropyValues.Brands = append(f.Signals.Browser.HighEntropyValues.Brands, fingerprintBrandVersion{
						Brand:   bv.GetBrand(),
						Version: bv.GetVersion(),
					})
				}
			}
			if tse := b.GetToSourceError(); tse != nil {
				f.Signals.Browser.ToSourceError = fingerprintBrowserToSourceError{
					ToSourceError: tse.GetToSourceError(),
					HasToSource:   FlexBool(tse.GetHasToSource()),
				}
			}
		}

		if g := s.GetGraphics(); g != nil {
			if gl := g.GetWebGL(); gl != nil {
				f.Signals.Graphics.WebGL = fingerprintGraphicsWebGL{
					Vendor:   gl.GetVendor(),
					Renderer: gl.GetRenderer(),
				}
			}
			if gpu := g.GetWebgpu(); gpu != nil {
				f.Signals.Graphics.WebGPU = fingerprintGraphicsWebGPU{
					Vendor:       gpu.GetVendor(),
					Architecture: gpu.GetArchitecture(),
					Device:       gpu.GetDevice(),
					Description:  gpu.GetDescription(),
				}
			}
			if cv := g.GetCanvas(); cv != nil {
				f.Signals.Graphics.Canvas = fingerprintGraphicsCanvas{
					HasModifiedCanvas: FlexBool(cv.GetHasModifiedCanvas()),
					CanvasFingerprint: cv.GetCanvasFingerprint(),
				}
			}
		}

		if c := s.GetCodecs(); c != nil {
			f.Signals.Codecs = fingerprintCodecs{
				AudioCanPlayTypeHash:     c.GetAudioCanPlayTypeHash(),
				VideoCanPlayTypeHash:     c.GetVideoCanPlayTypeHash(),
				AudioMediaSourceHash:     c.GetAudioMediaSourceHash(),
				VideoMediaSourceHash:     c.GetVideoMediaSourceHash(),
				RTCAudioCapabilitiesHash: c.GetRtcAudioCapabilitiesHash(),
				RTCVideoCapabilitiesHash: c.GetRtcVideoCapabilitiesHash(),
				HasMediaSource:           FlexBool(c.GetHasMediaSource()),
			}
		}

		if l := s.GetLocale(); l != nil {
			if i18n := l.GetInternationalization(); i18n != nil {
				f.Signals.Locale.Internationalization = fingerprintLocaleInternationalization{
					Timezone:       i18n.GetTimezone(),
					LocaleLanguage: i18n.GetLocaleLanguage(),
				}
			}
			if lang := l.GetLanguages(); lang != nil {
				f.Signals.Locale.Languages = fingerprintLocaleLanguages{
					Languages: lang.GetLanguages(),
					Language:  lang.GetLanguage(),
				}
			}
		}

		if ctx := s.GetContexts(); ctx != nil {
			if iframe := ctx.GetIframe(); iframe != nil {
				f.Signals.Contexts.Iframe = fingerprintIframeContext{
					Webdriver: FlexBool(iframe.GetWebdriver()),
					UserAgent: iframe.GetUserAgent(),
					Platform:  iframe.GetPlatform(),
					Memory:    FlexInt(iframe.GetMemory()),
					CPUCount:  FlexInt(iframe.GetCpuCount()),
					Language:  iframe.GetLanguage(),
				}
			}
			if ww := ctx.GetWebWorker(); ww != nil {
				f.Signals.Contexts.WebWorker = fingerprintWebWorkerContext{
					Vendor:    ww.GetVendor(),
					Renderer:  ww.GetRenderer(),
					UserAgent: ww.GetUserAgent(),
					Language:  ww.GetLanguage(),
					Platform:  ww.GetPlatform(),
					Memory:    FlexInt(ww.GetMemory()),
					CPUCount:  FlexInt(ww.GetCpuCount()),
				}
			}
		}
	}

	if det := p.GetFastBotDetectionDetails(); det != nil {
		f.FastBotDetectionDetails = fingerprintFastBotDetectionDetails{
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
		}
	}

	f.Bot = newFingerprintBotAlias(f.FastBotDetectionDetails)

	return f
}

func (f *FingerprintData) ToProto() *pb.FingerprintData {
	brands := make([]*pb.FingerprintBrandVersion, len(f.Signals.Browser.HighEntropyValues.Brands))
	for i, b := range f.Signals.Browser.HighEntropyValues.Brands {
		brands[i] = &pb.FingerprintBrandVersion{
			Brand:   b.Brand,
			Version: b.Version,
		}
	}

	return &pb.FingerprintData{
		Signals: &pb.FingerprintSignals{
			Automation: &pb.FingerprintAutomation{
				Webdriver:                    bool(f.Signals.Automation.Webdriver),
				WebdriverWritable:            bool(f.Signals.Automation.WebdriverWritable),
				Selenium:                     bool(f.Signals.Automation.Selenium),
				Cdp:                          bool(f.Signals.Automation.CDP),
				Playwright:                   bool(f.Signals.Automation.Playwright),
				NavigatorPropertyDescriptors: f.Signals.Automation.NavigatorPropertyDescriptors,
			},
			Device: &pb.FingerprintDevice{
				CpuCount: int32(f.Signals.Device.CPUCount),
				Memory:   int32(f.Signals.Device.Memory),
				Platform: f.Signals.Device.Platform,
				ScreenResolution: &pb.FingerprintScreenResolution{
					Width:               int32(f.Signals.Device.ScreenResolution.Width),
					Height:              int32(f.Signals.Device.ScreenResolution.Height),
					PixelDepth:          int32(f.Signals.Device.ScreenResolution.PixelDepth),
					ColorDepth:          int32(f.Signals.Device.ScreenResolution.ColorDepth),
					AvailableWidth:      int32(f.Signals.Device.ScreenResolution.AvailableWidth),
					AvailableHeight:     int32(f.Signals.Device.ScreenResolution.AvailableHeight),
					InnerWidth:          int32(f.Signals.Device.ScreenResolution.InnerWidth),
					InnerHeight:         int32(f.Signals.Device.ScreenResolution.InnerHeight),
					HasMultipleDisplays: bool(f.Signals.Device.ScreenResolution.HasMultipleDisplays),
				},
				MultimediaDevices: &pb.FingerprintMultimediaDevices{
					Speakers:    int32(f.Signals.Device.MultimediaDevices.Speakers),
					Microphones: int32(f.Signals.Device.MultimediaDevices.Microphones),
					Webcams:     int32(f.Signals.Device.MultimediaDevices.Webcams),
				},
				MediaQueries: &pb.FingerprintDeviceMediaQueries{
					PrefersColorScheme:         f.Signals.Device.MediaQueries.PrefersColorScheme,
					PrefersReducedMotion:       bool(f.Signals.Device.MediaQueries.PrefersReducedMotion),
					PrefersReducedTransparency: bool(f.Signals.Device.MediaQueries.PrefersReducedTransparency),
					ColorGamut:                 f.Signals.Device.MediaQueries.ColorGamut,
					Pointer:                    f.Signals.Device.MediaQueries.Pointer,
					AnyPointer:                 f.Signals.Device.MediaQueries.AnyPointer,
					Hover:                      bool(f.Signals.Device.MediaQueries.Hover),
					AnyHover:                   bool(f.Signals.Device.MediaQueries.AnyHover),
					ColorDepth:                 int32(f.Signals.Device.MediaQueries.ColorDepth),
				},
			},
			Browser: &pb.FingerprintBrowser{
				UserAgent: f.Signals.Browser.UserAgent,
				Features: &pb.FingerprintBrowserFeatures{
					Bitmask:         f.Signals.Browser.Features.Bitmask,
					Chrome:          bool(f.Signals.Browser.Features.Chrome),
					Brave:           bool(f.Signals.Browser.Features.Brave),
					ApplePaySupport: bool(f.Signals.Browser.Features.ApplePaySupport),
					Opera:           bool(f.Signals.Browser.Features.Opera),
					Serial:          bool(f.Signals.Browser.Features.Serial),
					AttachShadow:    bool(f.Signals.Browser.Features.AttachShadow),
					Caches:          bool(f.Signals.Browser.Features.Caches),
					WebAssembly:     bool(f.Signals.Browser.Features.WebAssembly),
					Buffer:          bool(f.Signals.Browser.Features.Buffer),
					ShowModalDialog: bool(f.Signals.Browser.Features.ShowModalDialog),
				},
				Plugins: &pb.FingerprintBrowserPlugins{
					IsValidPluginArray: bool(f.Signals.Browser.Plugins.IsValidPluginArray),
					PluginCount:        int32(f.Signals.Browser.Plugins.PluginCount),
					PluginNamesHash:    f.Signals.Browser.Plugins.PluginNamesHash,
					PluginConsistency1: bool(f.Signals.Browser.Plugins.PluginConsistency1),
					PluginOverflow:     bool(f.Signals.Browser.Plugins.PluginOverflow),
				},
				Extensions: &pb.FingerprintBrowserExtensions{
					Bitmask:    f.Signals.Browser.Extensions.Bitmask,
					Extensions: f.Signals.Browser.Extensions.Extensions,
				},
				HighEntropyValues: &pb.FingerprintBrowserHighEntropyValues{
					Architecture:    f.Signals.Browser.HighEntropyValues.Architecture,
					Bitness:         f.Signals.Browser.HighEntropyValues.Bitness,
					Brands:          brands,
					Mobile:          bool(f.Signals.Browser.HighEntropyValues.Mobile),
					Model:           f.Signals.Browser.HighEntropyValues.Model,
					Platform:        f.Signals.Browser.HighEntropyValues.Platform,
					PlatformVersion: f.Signals.Browser.HighEntropyValues.PlatformVersion,
					UaFullVersion:   f.Signals.Browser.HighEntropyValues.UAFullVersion,
				},
				Etsl:  int32(f.Signals.Browser.ETSL),
				Maths: f.Signals.Browser.Maths,
				ToSourceError: &pb.FingerprintBrowserToSourceError{
					ToSourceError: f.Signals.Browser.ToSourceError.ToSourceError,
					HasToSource:   bool(f.Signals.Browser.ToSourceError.HasToSource),
				},
			},
			Graphics: &pb.FingerprintGraphics{
				WebGL: &pb.FingerprintGraphicsWebGL{
					Vendor:   f.Signals.Graphics.WebGL.Vendor,
					Renderer: f.Signals.Graphics.WebGL.Renderer,
				},
				Webgpu: &pb.FingerprintGraphicsWebGPU{
					Vendor:       f.Signals.Graphics.WebGPU.Vendor,
					Architecture: f.Signals.Graphics.WebGPU.Architecture,
					Device:       f.Signals.Graphics.WebGPU.Device,
					Description:  f.Signals.Graphics.WebGPU.Description,
				},
				Canvas: &pb.FingerprintGraphicsCanvas{
					HasModifiedCanvas: bool(f.Signals.Graphics.Canvas.HasModifiedCanvas),
					CanvasFingerprint: f.Signals.Graphics.Canvas.CanvasFingerprint,
				},
			},
			Codecs: &pb.FingerprintCodecs{
				AudioCanPlayTypeHash:     f.Signals.Codecs.AudioCanPlayTypeHash,
				VideoCanPlayTypeHash:     f.Signals.Codecs.VideoCanPlayTypeHash,
				AudioMediaSourceHash:     f.Signals.Codecs.AudioMediaSourceHash,
				VideoMediaSourceHash:     f.Signals.Codecs.VideoMediaSourceHash,
				RtcAudioCapabilitiesHash: f.Signals.Codecs.RTCAudioCapabilitiesHash,
				RtcVideoCapabilitiesHash: f.Signals.Codecs.RTCVideoCapabilitiesHash,
				HasMediaSource:           bool(f.Signals.Codecs.HasMediaSource),
			},
			Locale: &pb.FingerprintLocale{
				Internationalization: &pb.FingerprintLocaleInternationalization{
					Timezone:       f.Signals.Locale.Internationalization.Timezone,
					LocaleLanguage: f.Signals.Locale.Internationalization.LocaleLanguage,
				},
				Languages: &pb.FingerprintLocaleLanguages{
					Languages: f.Signals.Locale.Languages.Languages,
					Language:  f.Signals.Locale.Languages.Language,
				},
			},
			Contexts: &pb.FingerprintContexts{
				Iframe: &pb.FingerprintIframeContext{
					Webdriver: bool(f.Signals.Contexts.Iframe.Webdriver),
					UserAgent: f.Signals.Contexts.Iframe.UserAgent,
					Platform:  f.Signals.Contexts.Iframe.Platform,
					Memory:    int32(f.Signals.Contexts.Iframe.Memory),
					CpuCount:  int32(f.Signals.Contexts.Iframe.CPUCount),
					Language:  f.Signals.Contexts.Iframe.Language,
				},
				WebWorker: &pb.FingerprintWebWorkerContext{
					Vendor:    f.Signals.Contexts.WebWorker.Vendor,
					Renderer:  f.Signals.Contexts.WebWorker.Renderer,
					UserAgent: f.Signals.Contexts.WebWorker.UserAgent,
					Language:  f.Signals.Contexts.WebWorker.Language,
					Platform:  f.Signals.Contexts.WebWorker.Platform,
					Memory:    int32(f.Signals.Contexts.WebWorker.Memory),
					CpuCount:  int32(f.Signals.Contexts.WebWorker.CPUCount),
				},
			},
		},
		Fsid:             f.FSID,
		Nonce:            f.Nonce,
		Time:             f.Time,
		Url:              f.URL,
		FastBotDetection: bool(f.FastBotDetection),
		FastBotDetectionDetails: &pb.FingerprintFastBotDetectionDetails{
			HeadlessChromeScreenResolution: &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HeadlessChromeScreenResolution.Detected)},
			HasWebdriver:                   &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasWebdriver.Detected)},
			HasWebdriverWritable:           &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasWebdriverWritable.Detected)},
			HasSeleniumProperty:            &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasSeleniumProperty.Detected)},
			HasCDP:                         &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasCDP.Detected)},
			HasPlaywright:                  &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasPlaywright.Detected)},
			HasImpossibleDeviceMemory:      &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasImpossibleDeviceMemory.Detected)},
			HasHighCPUCount:                &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasHighCPUCount.Detected)},
			HasMissingChromeObject:         &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasMissingChromeObject.Detected)},
			HasWebdriverIframe:             &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasWebdriverIframe.Detected)},
			HasWebdriverWorker:             &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasWebdriverWorker.Detected)},
			HasMismatchWebGLInWorker:       &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasMismatchWebGLInWorker.Detected)},
			HasMismatchPlatformIframe:      &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasMismatchPlatformIframe.Detected)},
			HasMismatchPlatformWorker:      &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasMismatchPlatformWorker.Detected)},
			HasSwiftshaderRenderer:         &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasSwiftshaderRenderer.Detected)},
			HasUTCTimezone:                 &pb.FingerprintDetectionResult{Detected: bool(f.FastBotDetectionDetails.HasUTCTimezone.Detected)},
		},
		Bot: &pb.FingerprintBotAlias{
			HeadlessChromeScreenResolution: f.Bot.HeadlessChromeScreenResolution,
			Webdriver:                      f.Bot.Webdriver,
			WebdriverWritable:              f.Bot.WebdriverWritable,
			Selenium:                       f.Bot.Selenium,
			Cdp:                            f.Bot.CDP,
			Playwright:                     f.Bot.Playwright,
			ImpossibleDeviceMemory:         f.Bot.ImpossibleDeviceMemory,
			HighCPUCount:                   f.Bot.HighCPUCount,
			MissingChromeObject:            f.Bot.MissingChromeObject,
			WebdriverIframe:                f.Bot.WebdriverIframe,
			WebdriverWorker:                f.Bot.WebdriverWorker,
			MismatchWebGLInWorker:          f.Bot.MismatchWebGLInWorker,
			MismatchPlatformIframe:         f.Bot.MismatchPlatformIframe,
			MismatchPlatformWorker:         f.Bot.MismatchPlatformWorker,
			SwiftshaderRenderer:            f.Bot.SwiftshaderRenderer,
			UtcTimezone:                    f.Bot.UTCTimezone,
			AnyDetected:                    f.Bot.AnyDetected,
			DetectedCount:                  int32(f.Bot.DetectedCount),
		},
	}
}
