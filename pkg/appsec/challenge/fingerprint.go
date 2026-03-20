package challenge

import "encoding/json"

/*
{
  "signals": {
    "automation": {
      "webdriver": false,
      "webdriverWritable": false,
      "selenium": false,
      "cdp": true,
      "playwright": false,
      "navigatorPropertyDescriptors": "00000"
    },
    "device": {
      "cpuCount": 14,
      "memory": 8,
      "platform": "MacIntel",
      "screenResolution": {
        "width": 2304,
        "height": 1296,
        "pixelDepth": 30,
        "colorDepth": 30,
        "availableWidth": 2304,
        "availableHeight": 1265,
        "innerWidth": 1444,
        "innerHeight": 1144,
        "hasMultipleDisplays": true
      },
      "multimediaDevices": {
        "speakers": 1,
        "microphones": 1,
        "webcams": 1
      },
      "mediaQueries": {
        "prefersColorScheme": "dark",
        "prefersReducedMotion": false,
        "prefersReducedTransparency": false,
        "colorGamut": "p3",
        "pointer": "fine",
        "anyPointer": "fine",
        "hover": true,
        "anyHover": true,
        "colorDepth": 10
      }
    },
    "browser": {
      "userAgent": "Mozilla/5.0+(Macintosh;+Intel+Mac+OS+X+10_15_7)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/144.0.0.0+Safari/537.36",
      "features": {
        "bitmask": "1000111100",
        "chrome": true,
        "brave": false,
        "applePaySupport": false,
        "opera": false,
        "serial": true,
        "attachShadow": true,
        "caches": true,
        "webAssembly": true,
        "buffer": false,
        "showModalDialog": false
      },
      "plugins": {
        "isValidPluginArray": true,
        "pluginCount": 5,
        "pluginNamesHash": "-2cdc5c8b",
        "pluginConsistency1": true,
        "pluginOverflow": false
      },
      "extensions": {
        "bitmask": "00000000",
        "extensions": []
      },
      "highEntropyValues": {
        "architecture": "arm",
        "bitness": "64",
        "brands": [
          {
            "brand": "Not(A:Brand",
            "version": "8"
          },
          {
            "brand": "Chromium",
            "version": "144"
          },
          {
            "brand": "Google+Chrome",
            "version": "144"
          }
        ],
        "mobile": false,
        "model": "",
        "platform": "macOS",
        "platformVersion": "26.2.0",
        "uaFullVersion": "144.0.7559.133"
      },
      "etsl": 33,
      "maths": "67d0b556",
      "toSourceError": {
        "toSourceError": "TypeError:+Cannot+read+properties+of+null+(reading+usdfsh)",
        "hasToSource": false
      }
    },
    "graphics": {
      "webGL": {
        "vendor": "Google+Inc.+(Apple)",
        "renderer": "ANGLE+(Apple,+ANGLE+Metal+Renderer:+Apple+M4+Max,+Unspecified+Version)"
      },
      "webgpu": {
        "vendor": "apple",
        "architecture": "metal-3",
        "device": "",
        "description": ""
      },
      "canvas": {
        "hasModifiedCanvas": false,
        "canvasFingerprint": "-421c84e0"
      }
    },
    "codecs": {
      "audioCanPlayTypeHash": "688c7345",
      "videoCanPlayTypeHash": "-126cde82",
      "audioMediaSourceHash": "-3cbc04a4",
      "videoMediaSourceHash": "-48c15d34",
      "rtcAudioCapabilitiesHash": "26a15cc5",
      "rtcVideoCapabilitiesHash": "4f24a817",
      "hasMediaSource": true
    },
    "locale": {
      "internationalization": {
        "timezone": "Europe/Paris",
        "localeLanguage": "en-US"
      },
      "languages": {
        "languages": [
          "en",
          "en-US",
          "fr-FR",
          "fr"
        ],
        "language": "en"
      }
    },
    "contexts": {
      "iframe": {
        "webdriver": false,
        "userAgent": "Mozilla/5.0+(Macintosh;+Intel+Mac+OS+X+10_15_7)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/144.0.0.0+Safari/537.36",
        "platform": "MacIntel",
        "memory": 8,
        "cpuCount": 14,
        "language": "en"
      },
      "webWorker": {
        "vendor": "Google+Inc.+(Apple)",
        "renderer": "ANGLE+(Apple,+ANGLE+Metal+Renderer:+Apple+M4+Max,+Unspecified+Version)",
        "userAgent": "Mozilla/5.0+(Macintosh;+Intel+Mac+OS+X+10_15_7)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/144.0.0.0+Safari/537.36",
        "language": "en",
        "platform": "MacIntel",
        "memory": 8,
        "cpuCount": 14
      }
    }
  },
  "fsid": "FS1_00001000000000_00010h02ba_2304x1296c14m08b10011h-5db59_f1000111100e00000000p1100h-7ce12_0h06653c_1h-36e6b_en4h720e_0100h-156f8",
  "nonce": "jb8t2jfm839",
  "time": 1770669806462,
  "url": "http://localhost/",
  "fastBotDetection": true,
  "fastBotDetectionDetails": {
    "headlessChromeScreenResolution": {
      "detected": false,
      "severity": "high"
    },
    "hasWebdriver": {
      "detected": false,
      "severity": "high"
    },
    "hasWebdriverWritable": {
      "detected": false,
      "severity": "high"
    },
    "hasSeleniumProperty": {
      "detected": false,
      "severity": "high"
    },
    "hasCDP": {
      "detected": true,
      "severity": "high"
    },
    "hasPlaywright": {
      "detected": false,
      "severity": "high"
    },
    "hasImpossibleDeviceMemory": {
      "detected": false,
      "severity": "high"
    },
    "hasHighCPUCount": {
      "detected": false,
      "severity": "high"
    },
    "hasMissingChromeObject": {
      "detected": false,
      "severity": "high"
    },
    "hasWebdriverIframe": {
      "detected": false,
      "severity": "high"
    },
    "hasWebdriverWorker": {
      "detected": false,
      "severity": "high"
    },
    "hasMismatchWebGLInWorker": {
      "detected": false,
      "severity": "high"
    },
    "hasMismatchPlatformIframe": {
      "detected": false,
      "severity": "high"
    },
    "hasMismatchPlatformWorker": {
      "detected": false,
      "severity": "high"
    },
    "hasSwiftshaderRenderer": {
      "detected": false,
      "severity": "low"
    },
    "hasUTCTimezone": {
      "detected": false,
      "severity": "medium"
    }
  }
}
*/

type FingerprintData struct {
	Signals                 fingerprintSignals                 `json:"signals"`
	FSID                    string                             `json:"fsid"`
	Nonce                   string                             `json:"nonce"`
	Time                    int64                              `json:"time"`
	URL                     string                             `json:"url"`
	FastBotDetection        bool                               `json:"fastBotDetection"`
	FastBotDetectionDetails fingerprintFastBotDetectionDetails `json:"fastBotDetectionDetails"`
	Bot                     fingerprintBotAlias                `json:"-"`
}

type fingerprintSignals struct {
	Automation fingerprintAutomation `json:"automation"`
	Device     fingerprintDevice     `json:"device"`
	Browser    fingerprintBrowser    `json:"browser"`
	Graphics   fingerprintGraphics   `json:"graphics"`
	Codecs     fingerprintCodecs     `json:"codecs"`
	Locale     fingerprintLocale     `json:"locale"`
	Contexts   fingerprintContexts   `json:"contexts"`
}

type fingerprintAutomation struct {
	Webdriver                    bool   `json:"webdriver"`
	WebdriverWritable            bool   `json:"webdriverWritable"`
	Selenium                     bool   `json:"selenium"`
	CDP                          bool   `json:"cdp"`
	Playwright                   bool   `json:"playwright"`
	NavigatorPropertyDescriptors string `json:"navigatorPropertyDescriptors"`
}

type fingerprintDevice struct {
	CPUCount          int                           `json:"cpuCount"`
	Memory            int                           `json:"memory"`
	Platform          string                        `json:"platform"`
	ScreenResolution  fingerprintScreenResolution   `json:"screenResolution"`
	MultimediaDevices fingerprintMultimediaDevices  `json:"multimediaDevices"`
	MediaQueries      fingerprintDeviceMediaQueries `json:"mediaQueries"`
}

type fingerprintScreenResolution struct {
	Width               int  `json:"width"`
	Height              int  `json:"height"`
	PixelDepth          int  `json:"pixelDepth"`
	ColorDepth          int  `json:"colorDepth"`
	AvailableWidth      int  `json:"availableWidth"`
	AvailableHeight     int  `json:"availableHeight"`
	InnerWidth          int  `json:"innerWidth"`
	InnerHeight         int  `json:"innerHeight"`
	HasMultipleDisplays bool `json:"hasMultipleDisplays"`
}

type fingerprintMultimediaDevices struct {
	Speakers    int `json:"speakers"`
	Microphones int `json:"microphones"`
	Webcams     int `json:"webcams"`
}

type fingerprintDeviceMediaQueries struct {
	PrefersColorScheme         string `json:"prefersColorScheme"`
	PrefersReducedMotion       bool   `json:"prefersReducedMotion"`
	PrefersReducedTransparency bool   `json:"prefersReducedTransparency"`
	ColorGamut                 string `json:"colorGamut"`
	Pointer                    string `json:"pointer"`
	AnyPointer                 string `json:"anyPointer"`
	Hover                      bool   `json:"hover"`
	AnyHover                   bool   `json:"anyHover"`
	ColorDepth                 int    `json:"colorDepth"`
}

type fingerprintBrowser struct {
	UserAgent         string                              `json:"userAgent"`
	Features          fingerprintBrowserFeatures          `json:"features"`
	Plugins           fingerprintBrowserPlugins           `json:"plugins"`
	Extensions        fingerprintBrowserExtensions        `json:"extensions"`
	HighEntropyValues fingerprintBrowserHighEntropyValues `json:"highEntropyValues"`
	ETSL              int                                 `json:"etsl"`
	Maths             string                              `json:"maths"`
	ToSourceError     fingerprintBrowserToSourceError     `json:"toSourceError"`
}

type fingerprintBrowserFeatures struct {
	Bitmask         string `json:"bitmask"`
	Chrome          bool   `json:"chrome"`
	Brave           bool   `json:"brave"`
	ApplePaySupport bool   `json:"applePaySupport"`
	Opera           bool   `json:"opera"`
	Serial          bool   `json:"serial"`
	AttachShadow    bool   `json:"attachShadow"`
	Caches          bool   `json:"caches"`
	WebAssembly     bool   `json:"webAssembly"`
	Buffer          bool   `json:"buffer"`
	ShowModalDialog bool   `json:"showModalDialog"`
}

type fingerprintBrowserPlugins struct {
	IsValidPluginArray bool   `json:"isValidPluginArray"`
	PluginCount        int    `json:"pluginCount"`
	PluginNamesHash    string `json:"pluginNamesHash"`
	PluginConsistency1 bool   `json:"pluginConsistency1"`
	PluginOverflow     bool   `json:"pluginOverflow"`
}

type fingerprintBrowserExtensions struct {
	Bitmask    string   `json:"bitmask"`
	Extensions []string `json:"extensions"`
}

type fingerprintBrowserHighEntropyValues struct {
	Architecture    string                    `json:"architecture"`
	Bitness         string                    `json:"bitness"`
	Brands          []fingerprintBrandVersion `json:"brands"`
	Mobile          bool                      `json:"mobile"`
	Model           string                    `json:"model"`
	Platform        string                    `json:"platform"`
	PlatformVersion string                    `json:"platformVersion"`
	UAFullVersion   string                    `json:"uaFullVersion"`
}

type fingerprintBrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type fingerprintBrowserToSourceError struct {
	ToSourceError string `json:"toSourceError"`
	HasToSource   bool   `json:"hasToSource"`
}

type fingerprintGraphics struct {
	WebGL  fingerprintGraphicsWebGL  `json:"webGL"`
	WebGPU fingerprintGraphicsWebGPU `json:"webgpu"`
	Canvas fingerprintGraphicsCanvas `json:"canvas"`
}

type fingerprintGraphicsWebGL struct {
	Vendor   string `json:"vendor"`
	Renderer string `json:"renderer"`
}

type fingerprintGraphicsWebGPU struct {
	Vendor       string `json:"vendor"`
	Architecture string `json:"architecture"`
	Device       string `json:"device"`
	Description  string `json:"description"`
}

type fingerprintGraphicsCanvas struct {
	HasModifiedCanvas bool   `json:"hasModifiedCanvas"`
	CanvasFingerprint string `json:"canvasFingerprint"`
}

type fingerprintCodecs struct {
	AudioCanPlayTypeHash     string `json:"audioCanPlayTypeHash"`
	VideoCanPlayTypeHash     string `json:"videoCanPlayTypeHash"`
	AudioMediaSourceHash     string `json:"audioMediaSourceHash"`
	VideoMediaSourceHash     string `json:"videoMediaSourceHash"`
	RTCAudioCapabilitiesHash string `json:"rtcAudioCapabilitiesHash"`
	RTCVideoCapabilitiesHash string `json:"rtcVideoCapabilitiesHash"`
	HasMediaSource           bool   `json:"hasMediaSource"`
}

type fingerprintLocale struct {
	Internationalization fingerprintLocaleInternationalization `json:"internationalization"`
	Languages            fingerprintLocaleLanguages            `json:"languages"`
}

type fingerprintLocaleInternationalization struct {
	Timezone       string `json:"timezone"`
	LocaleLanguage string `json:"localeLanguage"`
}

type fingerprintLocaleLanguages struct {
	Languages []string `json:"languages"`
	Language  string   `json:"language"`
}

type fingerprintContexts struct {
	Iframe    fingerprintIframeContext    `json:"iframe"`
	WebWorker fingerprintWebWorkerContext `json:"webWorker"`
}

type fingerprintIframeContext struct {
	Webdriver bool   `json:"webdriver"`
	UserAgent string `json:"userAgent"`
	Platform  string `json:"platform"`
	Memory    int    `json:"memory"`
	CPUCount  int    `json:"cpuCount"`
	Language  string `json:"language"`
}

type fingerprintWebWorkerContext struct {
	Vendor    string `json:"vendor"`
	Renderer  string `json:"renderer"`
	UserAgent string `json:"userAgent"`
	Language  string `json:"language"`
	Platform  string `json:"platform"`
	Memory    int    `json:"memory"`
	CPUCount  int    `json:"cpuCount"`
}

type fingerprintFastBotDetectionDetails struct {
	HeadlessChromeScreenResolution fingerprintDetectionResult `json:"headlessChromeScreenResolution"`
	HasWebdriver                   fingerprintDetectionResult `json:"hasWebdriver"`
	HasWebdriverWritable           fingerprintDetectionResult `json:"hasWebdriverWritable"`
	HasSeleniumProperty            fingerprintDetectionResult `json:"hasSeleniumProperty"`
	HasCDP                         fingerprintDetectionResult `json:"hasCDP"`
	HasPlaywright                  fingerprintDetectionResult `json:"hasPlaywright"`
	HasImpossibleDeviceMemory      fingerprintDetectionResult `json:"hasImpossibleDeviceMemory"`
	HasHighCPUCount                fingerprintDetectionResult `json:"hasHighCPUCount"`
	HasMissingChromeObject         fingerprintDetectionResult `json:"hasMissingChromeObject"`
	HasWebdriverIframe             fingerprintDetectionResult `json:"hasWebdriverIframe"`
	HasWebdriverWorker             fingerprintDetectionResult `json:"hasWebdriverWorker"`
	HasMismatchWebGLInWorker       fingerprintDetectionResult `json:"hasMismatchWebGLInWorker"`
	HasMismatchPlatformIframe      fingerprintDetectionResult `json:"hasMismatchPlatformIframe"`
	HasMismatchPlatformWorker      fingerprintDetectionResult `json:"hasMismatchPlatformWorker"`
	HasSwiftshaderRenderer         fingerprintDetectionResult `json:"hasSwiftshaderRenderer"`
	HasUTCTimezone                 fingerprintDetectionResult `json:"hasUTCTimezone"`
}

type fingerprintDetectionResult struct {
	Detected bool `json:"detected"`
}

type fingerprintBotAlias struct {
	HeadlessChromeScreenResolution bool `json:"headlessChromeScreenResolution"`
	Webdriver                      bool `json:"webdriver"`
	WebdriverWritable              bool `json:"webdriverWritable"`
	Selenium                       bool `json:"selenium"`
	CDP                            bool `json:"cdp"`
	Playwright                     bool `json:"playwright"`
	ImpossibleDeviceMemory         bool `json:"impossibleDeviceMemory"`
	HighCPUCount                   bool `json:"highCPUCount"`
	MissingChromeObject            bool `json:"missingChromeObject"`
	WebdriverIframe                bool `json:"webdriverIframe"`
	WebdriverWorker                bool `json:"webdriverWorker"`
	MismatchWebGLInWorker          bool `json:"mismatchWebGLInWorker"`
	MismatchPlatformIframe         bool `json:"mismatchPlatformIframe"`
	MismatchPlatformWorker         bool `json:"mismatchPlatformWorker"`
	SwiftshaderRenderer            bool `json:"swiftshaderRenderer"`
	UTCTimezone                    bool `json:"utcTimezone"`
	AnyDetected                    bool `json:"anyDetected"`
	DetectedCount                  int  `json:"detectedCount"`
}

func (f *FingerprintData) UnmarshalJSON(data []byte) error {
	type rawFingerprintData FingerprintData

	var raw rawFingerprintData
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*f = FingerprintData(raw)
	f.Bot = newFingerprintBotAlias(f.FastBotDetectionDetails)

	return nil
}

func newFingerprintBotAlias(details fingerprintFastBotDetectionDetails) fingerprintBotAlias {
	alias := fingerprintBotAlias{
		HeadlessChromeScreenResolution: details.HeadlessChromeScreenResolution.Detected,
		Webdriver:                      details.HasWebdriver.Detected,
		WebdriverWritable:              details.HasWebdriverWritable.Detected,
		Selenium:                       details.HasSeleniumProperty.Detected,
		CDP:                            details.HasCDP.Detected,
		Playwright:                     details.HasPlaywright.Detected,
		ImpossibleDeviceMemory:         details.HasImpossibleDeviceMemory.Detected,
		HighCPUCount:                   details.HasHighCPUCount.Detected,
		MissingChromeObject:            details.HasMissingChromeObject.Detected,
		WebdriverIframe:                details.HasWebdriverIframe.Detected,
		WebdriverWorker:                details.HasWebdriverWorker.Detected,
		MismatchWebGLInWorker:          details.HasMismatchWebGLInWorker.Detected,
		MismatchPlatformIframe:         details.HasMismatchPlatformIframe.Detected,
		MismatchPlatformWorker:         details.HasMismatchPlatformWorker.Detected,
		SwiftshaderRenderer:            details.HasSwiftshaderRenderer.Detected,
		UTCTimezone:                    details.HasUTCTimezone.Detected,
	}

	if alias.HeadlessChromeScreenResolution {
		alias.DetectedCount++
	}
	if alias.Webdriver {
		alias.DetectedCount++
	}
	if alias.WebdriverWritable {
		alias.DetectedCount++
	}
	if alias.Selenium {
		alias.DetectedCount++
	}
	if alias.CDP {
		alias.DetectedCount++
	}
	if alias.Playwright {
		alias.DetectedCount++
	}
	if alias.ImpossibleDeviceMemory {
		alias.DetectedCount++
	}
	if alias.HighCPUCount {
		alias.DetectedCount++
	}
	if alias.MissingChromeObject {
		alias.DetectedCount++
	}
	if alias.WebdriverIframe {
		alias.DetectedCount++
	}
	if alias.WebdriverWorker {
		alias.DetectedCount++
	}
	if alias.MismatchWebGLInWorker {
		alias.DetectedCount++
	}
	if alias.MismatchPlatformIframe {
		alias.DetectedCount++
	}
	if alias.MismatchPlatformWorker {
		alias.DetectedCount++
	}
	if alias.SwiftshaderRenderer {
		alias.DetectedCount++
	}
	if alias.UTCTimezone {
		alias.DetectedCount++
	}

	alias.AnyDetected = alias.DetectedCount > 0

	return alias
}
