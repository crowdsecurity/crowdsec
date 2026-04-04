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
		FastBotDetection: p.GetFastBotDetection(),
	}

	if s := p.GetSignals(); s != nil {
		if a := s.GetAutomation(); a != nil {
			f.Signals.Automation = fingerprintAutomation{
				Webdriver:                    a.GetWebdriver(),
				WebdriverWritable:            a.GetWebdriverWritable(),
				Selenium:                     a.GetSelenium(),
				CDP:                          a.GetCdp(),
				Playwright:                   a.GetPlaywright(),
				NavigatorPropertyDescriptors: a.GetNavigatorPropertyDescriptors(),
			}
		}

		if d := s.GetDevice(); d != nil {
			f.Signals.Device = fingerprintDevice{
				CPUCount: int(d.GetCpuCount()),
				Memory:   int(d.GetMemory()),
				Platform: d.GetPlatform(),
			}
			if sr := d.GetScreenResolution(); sr != nil {
				f.Signals.Device.ScreenResolution = fingerprintScreenResolution{
					Width:               int(sr.GetWidth()),
					Height:              int(sr.GetHeight()),
					PixelDepth:          int(sr.GetPixelDepth()),
					ColorDepth:          int(sr.GetColorDepth()),
					AvailableWidth:      int(sr.GetAvailableWidth()),
					AvailableHeight:     int(sr.GetAvailableHeight()),
					InnerWidth:          int(sr.GetInnerWidth()),
					InnerHeight:         int(sr.GetInnerHeight()),
					HasMultipleDisplays: sr.GetHasMultipleDisplays(),
				}
			}
			if mm := d.GetMultimediaDevices(); mm != nil {
				f.Signals.Device.MultimediaDevices = fingerprintMultimediaDevices{
					Speakers:    int(mm.GetSpeakers()),
					Microphones: int(mm.GetMicrophones()),
					Webcams:     int(mm.GetWebcams()),
				}
			}
			if mq := d.GetMediaQueries(); mq != nil {
				f.Signals.Device.MediaQueries = fingerprintDeviceMediaQueries{
					PrefersColorScheme:         mq.GetPrefersColorScheme(),
					PrefersReducedMotion:       mq.GetPrefersReducedMotion(),
					PrefersReducedTransparency: mq.GetPrefersReducedTransparency(),
					ColorGamut:                 mq.GetColorGamut(),
					Pointer:                    mq.GetPointer(),
					AnyPointer:                 mq.GetAnyPointer(),
					Hover:                      mq.GetHover(),
					AnyHover:                   mq.GetAnyHover(),
					ColorDepth:                 int(mq.GetColorDepth()),
				}
			}
		}

		if b := s.GetBrowser(); b != nil {
			f.Signals.Browser = fingerprintBrowser{
				UserAgent: b.GetUserAgent(),
				ETSL:      int(b.GetEtsl()),
				Maths:     b.GetMaths(),
			}
			if ft := b.GetFeatures(); ft != nil {
				f.Signals.Browser.Features = fingerprintBrowserFeatures{
					Bitmask:         ft.GetBitmask(),
					Chrome:          ft.GetChrome(),
					Brave:           ft.GetBrave(),
					ApplePaySupport: ft.GetApplePaySupport(),
					Opera:           ft.GetOpera(),
					Serial:          ft.GetSerial(),
					AttachShadow:    ft.GetAttachShadow(),
					Caches:          ft.GetCaches(),
					WebAssembly:     ft.GetWebAssembly(),
					Buffer:          ft.GetBuffer(),
					ShowModalDialog: ft.GetShowModalDialog(),
				}
			}
			if pl := b.GetPlugins(); pl != nil {
				f.Signals.Browser.Plugins = fingerprintBrowserPlugins{
					IsValidPluginArray: pl.GetIsValidPluginArray(),
					PluginCount:        int(pl.GetPluginCount()),
					PluginNamesHash:    pl.GetPluginNamesHash(),
					PluginConsistency1: pl.GetPluginConsistency1(),
					PluginOverflow:     pl.GetPluginOverflow(),
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
					Mobile:          hev.GetMobile(),
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
					HasToSource:   tse.GetHasToSource(),
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
					HasModifiedCanvas: cv.GetHasModifiedCanvas(),
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
				HasMediaSource:           c.GetHasMediaSource(),
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
					Webdriver: iframe.GetWebdriver(),
					UserAgent: iframe.GetUserAgent(),
					Platform:  iframe.GetPlatform(),
					Memory:    int(iframe.GetMemory()),
					CPUCount:  int(iframe.GetCpuCount()),
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
					Memory:    int(ww.GetMemory()),
					CPUCount:  int(ww.GetCpuCount()),
				}
			}
		}
	}

	if det := p.GetFastBotDetectionDetails(); det != nil {
		f.FastBotDetectionDetails = fingerprintFastBotDetectionDetails{
			HeadlessChromeScreenResolution: fingerprintDetectionResult{Detected: det.GetHeadlessChromeScreenResolution().GetDetected()},
			HasWebdriver:                   fingerprintDetectionResult{Detected: det.GetHasWebdriver().GetDetected()},
			HasWebdriverWritable:           fingerprintDetectionResult{Detected: det.GetHasWebdriverWritable().GetDetected()},
			HasSeleniumProperty:            fingerprintDetectionResult{Detected: det.GetHasSeleniumProperty().GetDetected()},
			HasCDP:                         fingerprintDetectionResult{Detected: det.GetHasCDP().GetDetected()},
			HasPlaywright:                  fingerprintDetectionResult{Detected: det.GetHasPlaywright().GetDetected()},
			HasImpossibleDeviceMemory:      fingerprintDetectionResult{Detected: det.GetHasImpossibleDeviceMemory().GetDetected()},
			HasHighCPUCount:                fingerprintDetectionResult{Detected: det.GetHasHighCPUCount().GetDetected()},
			HasMissingChromeObject:         fingerprintDetectionResult{Detected: det.GetHasMissingChromeObject().GetDetected()},
			HasWebdriverIframe:             fingerprintDetectionResult{Detected: det.GetHasWebdriverIframe().GetDetected()},
			HasWebdriverWorker:             fingerprintDetectionResult{Detected: det.GetHasWebdriverWorker().GetDetected()},
			HasMismatchWebGLInWorker:       fingerprintDetectionResult{Detected: det.GetHasMismatchWebGLInWorker().GetDetected()},
			HasMismatchPlatformIframe:      fingerprintDetectionResult{Detected: det.GetHasMismatchPlatformIframe().GetDetected()},
			HasMismatchPlatformWorker:      fingerprintDetectionResult{Detected: det.GetHasMismatchPlatformWorker().GetDetected()},
			HasSwiftshaderRenderer:         fingerprintDetectionResult{Detected: det.GetHasSwiftshaderRenderer().GetDetected()},
			HasUTCTimezone:                 fingerprintDetectionResult{Detected: det.GetHasUTCTimezone().GetDetected()},
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
				Webdriver:                    f.Signals.Automation.Webdriver,
				WebdriverWritable:            f.Signals.Automation.WebdriverWritable,
				Selenium:                     f.Signals.Automation.Selenium,
				Cdp:                          f.Signals.Automation.CDP,
				Playwright:                   f.Signals.Automation.Playwright,
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
					HasMultipleDisplays: f.Signals.Device.ScreenResolution.HasMultipleDisplays,
				},
				MultimediaDevices: &pb.FingerprintMultimediaDevices{
					Speakers:    int32(f.Signals.Device.MultimediaDevices.Speakers),
					Microphones: int32(f.Signals.Device.MultimediaDevices.Microphones),
					Webcams:     int32(f.Signals.Device.MultimediaDevices.Webcams),
				},
				MediaQueries: &pb.FingerprintDeviceMediaQueries{
					PrefersColorScheme:         f.Signals.Device.MediaQueries.PrefersColorScheme,
					PrefersReducedMotion:       f.Signals.Device.MediaQueries.PrefersReducedMotion,
					PrefersReducedTransparency: f.Signals.Device.MediaQueries.PrefersReducedTransparency,
					ColorGamut:                 f.Signals.Device.MediaQueries.ColorGamut,
					Pointer:                    f.Signals.Device.MediaQueries.Pointer,
					AnyPointer:                 f.Signals.Device.MediaQueries.AnyPointer,
					Hover:                      f.Signals.Device.MediaQueries.Hover,
					AnyHover:                   f.Signals.Device.MediaQueries.AnyHover,
					ColorDepth:                 int32(f.Signals.Device.MediaQueries.ColorDepth),
				},
			},
			Browser: &pb.FingerprintBrowser{
				UserAgent: f.Signals.Browser.UserAgent,
				Features: &pb.FingerprintBrowserFeatures{
					Bitmask:         f.Signals.Browser.Features.Bitmask,
					Chrome:          f.Signals.Browser.Features.Chrome,
					Brave:           f.Signals.Browser.Features.Brave,
					ApplePaySupport: f.Signals.Browser.Features.ApplePaySupport,
					Opera:           f.Signals.Browser.Features.Opera,
					Serial:          f.Signals.Browser.Features.Serial,
					AttachShadow:    f.Signals.Browser.Features.AttachShadow,
					Caches:          f.Signals.Browser.Features.Caches,
					WebAssembly:     f.Signals.Browser.Features.WebAssembly,
					Buffer:          f.Signals.Browser.Features.Buffer,
					ShowModalDialog: f.Signals.Browser.Features.ShowModalDialog,
				},
				Plugins: &pb.FingerprintBrowserPlugins{
					IsValidPluginArray: f.Signals.Browser.Plugins.IsValidPluginArray,
					PluginCount:        int32(f.Signals.Browser.Plugins.PluginCount),
					PluginNamesHash:    f.Signals.Browser.Plugins.PluginNamesHash,
					PluginConsistency1: f.Signals.Browser.Plugins.PluginConsistency1,
					PluginOverflow:     f.Signals.Browser.Plugins.PluginOverflow,
				},
				Extensions: &pb.FingerprintBrowserExtensions{
					Bitmask:    f.Signals.Browser.Extensions.Bitmask,
					Extensions: f.Signals.Browser.Extensions.Extensions,
				},
				HighEntropyValues: &pb.FingerprintBrowserHighEntropyValues{
					Architecture:    f.Signals.Browser.HighEntropyValues.Architecture,
					Bitness:         f.Signals.Browser.HighEntropyValues.Bitness,
					Brands:          brands,
					Mobile:          f.Signals.Browser.HighEntropyValues.Mobile,
					Model:           f.Signals.Browser.HighEntropyValues.Model,
					Platform:        f.Signals.Browser.HighEntropyValues.Platform,
					PlatformVersion: f.Signals.Browser.HighEntropyValues.PlatformVersion,
					UaFullVersion:   f.Signals.Browser.HighEntropyValues.UAFullVersion,
				},
				Etsl:  int32(f.Signals.Browser.ETSL),
				Maths: f.Signals.Browser.Maths,
				ToSourceError: &pb.FingerprintBrowserToSourceError{
					ToSourceError: f.Signals.Browser.ToSourceError.ToSourceError,
					HasToSource:   f.Signals.Browser.ToSourceError.HasToSource,
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
					HasModifiedCanvas: f.Signals.Graphics.Canvas.HasModifiedCanvas,
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
				HasMediaSource:           f.Signals.Codecs.HasMediaSource,
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
					Webdriver: f.Signals.Contexts.Iframe.Webdriver,
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
		FastBotDetection: f.FastBotDetection,
		FastBotDetectionDetails: &pb.FingerprintFastBotDetectionDetails{
			HeadlessChromeScreenResolution: &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HeadlessChromeScreenResolution.Detected},
			HasWebdriver:                   &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasWebdriver.Detected},
			HasWebdriverWritable:           &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasWebdriverWritable.Detected},
			HasSeleniumProperty:            &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasSeleniumProperty.Detected},
			HasCDP:                         &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasCDP.Detected},
			HasPlaywright:                  &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasPlaywright.Detected},
			HasImpossibleDeviceMemory:      &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasImpossibleDeviceMemory.Detected},
			HasHighCPUCount:                &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasHighCPUCount.Detected},
			HasMissingChromeObject:         &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasMissingChromeObject.Detected},
			HasWebdriverIframe:             &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasWebdriverIframe.Detected},
			HasWebdriverWorker:             &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasWebdriverWorker.Detected},
			HasMismatchWebGLInWorker:       &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasMismatchWebGLInWorker.Detected},
			HasMismatchPlatformIframe:      &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasMismatchPlatformIframe.Detected},
			HasMismatchPlatformWorker:      &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasMismatchPlatformWorker.Detected},
			HasSwiftshaderRenderer:         &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasSwiftshaderRenderer.Detected},
			HasUTCTimezone:                 &pb.FingerprintDetectionResult{Detected: f.FastBotDetectionDetails.HasUTCTimezone.Detected},
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
