import { ERROR, INIT, NA } from './signals/utils';

export type SignalValue<T> = T | typeof ERROR | typeof INIT | typeof NA;

export interface WebGLSignal {
    vendor: SignalValue<string>;
    renderer: SignalValue<string>;
}

export interface InternationalizationSignal {
    timezone: SignalValue<string>;
    localeLanguage: SignalValue<string>;
}

export interface ScreenResolutionSignal {
    width: SignalValue<number>;
    height: SignalValue<number>;
    pixelDepth: SignalValue<number>;
    colorDepth: SignalValue<number>;
    availableWidth: SignalValue<number>;
    availableHeight: SignalValue<number>;
    innerWidth: SignalValue<number>;
    innerHeight: SignalValue<number>;
    hasMultipleDisplays: SignalValue<boolean>;
}

export interface LanguagesSignal {
    languages: SignalValue<string[]>;
    language: SignalValue<string>;
}

export interface WebGPUSignal {
    vendor: SignalValue<string>;
    architecture: SignalValue<string>;
    device: SignalValue<string>;
    description: SignalValue<string>;
}

export interface IframeSignal {
    webdriver: SignalValue<boolean>;
    userAgent: SignalValue<string>;
    platform: SignalValue<string>;
    memory: SignalValue<number>;
    cpuCount: SignalValue<number>;
    language: SignalValue<string>;
}

export interface WebWorkerSignal {
    webdriver: SignalValue<boolean>;
    userAgent: SignalValue<string>;
    platform: SignalValue<string>;
    memory: SignalValue<number>;
    cpuCount: SignalValue<number>;
    language: SignalValue<string>;
    vendor: SignalValue<string>;
    renderer: SignalValue<string>;
}

export interface BrowserExtensionsSignal {
    bitmask: SignalValue<string>;
    extensions: SignalValue<string[]>;
}

export interface BrowserFeaturesSignal {
    bitmask: SignalValue<string>;
    chrome: SignalValue<boolean>;
    brave: SignalValue<boolean>;
    applePaySupport: SignalValue<boolean>;
    opera: SignalValue<boolean>;
    serial: SignalValue<boolean>;
    attachShadow: SignalValue<boolean>;
    caches: SignalValue<boolean>;
    webAssembly: SignalValue<boolean>;
    buffer: SignalValue<boolean>;
    showModalDialog: SignalValue<boolean>;
}

export interface MediaQueriesSignal {
    prefersColorScheme: SignalValue<string | null>;
    prefersReducedMotion: SignalValue<boolean>;
    prefersReducedTransparency: SignalValue<boolean>;
    colorGamut: SignalValue<string | null>;
    pointer: SignalValue<string | null>;
    anyPointer: SignalValue<string | null>;
    hover: SignalValue<boolean>;
    anyHover: SignalValue<boolean>;
    colorDepth: SignalValue<number>;
}

export interface ToSourceErrorSignal {
    toSourceError: SignalValue<string>;
    hasToSource: SignalValue<boolean>;
}

export interface CanvasSignal {
    hasModifiedCanvas: SignalValue<boolean>;
    canvasFingerprint: SignalValue<string>;
}

export interface HighEntropyValuesSignal {
    architecture: SignalValue<string>;
    bitness: SignalValue<string>;
    brands: SignalValue<string[]>;
    mobile: SignalValue<boolean>;
    model: SignalValue<string>;
    platform: SignalValue<string>;
    platformVersion: SignalValue<string>;
    uaFullVersion: SignalValue<string>;
}

export interface PluginsSignal {
    isValidPluginArray: SignalValue<boolean>;
    pluginCount: SignalValue<number>;
    pluginNamesHash: SignalValue<string>;
    pluginConsistency1: SignalValue<boolean>;
    pluginOverflow: SignalValue<boolean>;
}

export interface MultimediaDevicesSignal {
    speakers: SignalValue<number>;
    microphones: SignalValue<number>;
    webcams: SignalValue<number>;
}

export interface MediaCodecsSignal {
    audioCanPlayTypeHash: SignalValue<string>;
    videoCanPlayTypeHash: SignalValue<string>;
    audioMediaSourceHash: SignalValue<string>;
    videoMediaSourceHash: SignalValue<string>;
    rtcAudioCapabilitiesHash: SignalValue<string>;
    rtcVideoCapabilitiesHash: SignalValue<string>;
    hasMediaSource: SignalValue<boolean>;
}

// Grouped signal interfaces
export interface AutomationSignals {
    webdriver: SignalValue<boolean>;
    webdriverWritable: SignalValue<boolean>;
    selenium: SignalValue<boolean>;
    cdp: SignalValue<boolean>;
    playwright: SignalValue<boolean>;
    navigatorPropertyDescriptors: SignalValue<string>;
}

export interface DeviceSignals {
    cpuCount: SignalValue<number>;
    memory: SignalValue<number>;
    platform: SignalValue<string>;
    screenResolution: ScreenResolutionSignal;
    multimediaDevices: MultimediaDevicesSignal;
    mediaQueries: MediaQueriesSignal;
}

export interface BrowserSignals {
    userAgent: SignalValue<string>;
    features: BrowserFeaturesSignal;
    plugins: PluginsSignal;
    extensions: BrowserExtensionsSignal;
    highEntropyValues: HighEntropyValuesSignal;
    etsl: SignalValue<number>;
    maths: SignalValue<string>;
    toSourceError: ToSourceErrorSignal;
}

export interface GraphicsSignals {
    webGL: WebGLSignal;
    webgpu: WebGPUSignal;
    canvas: CanvasSignal;
}

export interface LocaleSignals {
    internationalization: InternationalizationSignal;
    languages: LanguagesSignal;
}

export interface ContextsSignals {
    iframe: IframeSignal;
    webWorker: WebWorkerSignal;
}

export interface FingerprintSignals {
    automation: AutomationSignals;
    device: DeviceSignals;
    browser: BrowserSignals;
    graphics: GraphicsSignals;
    codecs: MediaCodecsSignal;
    locale: LocaleSignals;
    contexts: ContextsSignals;
}

export interface FastBotDetectionDetails {
    headlessChromeScreenResolution: DetectionRuleResult;
    hasWebdriver: DetectionRuleResult;
    hasWebdriverWritable: DetectionRuleResult;
    hasSeleniumProperty: DetectionRuleResult;
    hasCDP: DetectionRuleResult;
    hasPlaywright: DetectionRuleResult;
    hasImpossibleDeviceMemory: DetectionRuleResult;
    hasHighCPUCount: DetectionRuleResult;
    hasMissingChromeObject: DetectionRuleResult;
    hasWebdriverIframe: DetectionRuleResult;
    hasWebdriverWorker: DetectionRuleResult;
    hasMismatchWebGLInWorker: DetectionRuleResult;
    hasMismatchPlatformIframe: DetectionRuleResult;
    hasMismatchPlatformWorker: DetectionRuleResult;
}
export interface Fingerprint {
    signals: FingerprintSignals;
    fsid: string;
    nonce: string;
    time: SignalValue<number>;
    url: string;
    fastBotDetection: boolean;
    fastBotDetectionDetails: FastBotDetectionDetails;
}

export type DetectionSeverity = 'low' | 'medium' | 'high';

export interface DetectionRuleResult {
    detected: boolean;
    severity: DetectionSeverity;
}

export interface DetectionRule {
    name: string;
    severity: DetectionSeverity;
    test: (fingerprint: Fingerprint) => boolean;
}

export interface CollectFingerprintOptions {
    encrypt?: boolean;
    timeout?: number;
}

