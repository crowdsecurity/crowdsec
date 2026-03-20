// Import all signals
import { webdriver } from './signals/webdriver';
import { userAgent } from './signals/userAgent';
import { platform } from './signals/platform';
import { cdp } from './signals/cdp';
import { webGL } from './signals/webGL';
import { playwright } from './signals/playwright';
import { cpuCount } from './signals/cpuCount';
import { maths } from './signals/maths';
import { memory } from './signals/memory';
import { etsl } from './signals/etsl';
import { internationalization } from './signals/internationalization';
import { screenResolution } from './signals/screenResolution';
import { languages } from './signals/languages';
import { webgpu } from './signals/webgpu';
import { hasSeleniumProperties } from './signals/seleniumProperties';
import { webdriverWritable } from './signals/webdriverWritable';
import { highEntropyValues } from './signals/highEntropyValues';
import { plugins } from './signals/plugins';
import { multimediaDevices } from './signals/multimediaDevices';
import { iframe } from './signals/iframe';
import { worker } from './signals/worker';
import { toSourceError } from './signals/toSourceError';
import { mediaCodecs } from './signals/mediaCodecs';
import { canvas } from './signals/canvas';
import { navigatorPropertyDescriptors } from './signals/navigatorPropertyDescriptors';
import { nonce } from './signals/nonce';
import { time } from './signals/time';
import { pageURL } from './signals/url';
import { hasContextMismatch } from './detections/hasContextMismatch';
import { browserExtensions } from './signals/browserExtensions';
import { browserFeatures } from './signals/browserFeatures';
import { mediaQueries } from './signals/mediaQueries';

// Fast Bot Detection tests
import { hasHeadlessChromeScreenResolution } from './detections/hasHeadlessChromeScreenResolution';
import { hasWebdriver } from './detections/hasWebdriver';
import { hasSeleniumProperty } from './detections/hasSeleniumProperty';
import { hasCDP } from './detections/hasCDP';
import { hasPlaywright } from './detections/hasPlaywright';
import { hasImpossibleDeviceMemory } from './detections/hasImpossibleDeviceMemory';
import { hasHighCPUCount } from './detections/hasHighCPUCount';
import { hasMissingChromeObject } from './detections/hasMissingChromeObject';
import { hasWebdriverIframe } from './detections/hasWebdriverIframe';
import { hasWebdriverWorker } from './detections/hasWebdriverWorker';
import { hasMismatchWebGLInWorker } from './detections/hasMismatchWebGLInWorker';
import { hasMismatchPlatformWorker } from './detections/hasMismatchPlatformWorker';
import { hasMismatchPlatformIframe } from './detections/hasMismatchPlatformIframe';
import { hasWebdriverWritable } from './detections/hasWebdriverWritable';
import { hasSwiftshaderRenderer } from './detections/hasSwiftshaderRenderer';
import { hasUTCTimezone } from './detections/hasUTCTimezone';

import { ERROR, HIGH, INIT, LOW, MEDIUM, hashCode } from './signals/utils';
import { encryptString } from './crypto-helpers';
import { Fingerprint, FastBotDetectionDetails, DetectionRule, CollectFingerprintOptions } from './types';


class FingerprintScanner {
    private fingerprint: Fingerprint;

    constructor() {
        this.fingerprint = {
            signals: {
                // Automation/Bot detection signals
                automation: {
                    webdriver: INIT,
                    webdriverWritable: INIT,
                    selenium: INIT,
                    cdp: INIT,
                    playwright: INIT,
                    navigatorPropertyDescriptors: INIT,
                },
                // Device hardware characteristics
                device: {
                    cpuCount: INIT,
                    memory: INIT,
                    platform: INIT,
                    screenResolution: {
                        width: INIT,
                        height: INIT,
                        pixelDepth: INIT,
                        colorDepth: INIT,
                        availableWidth: INIT,
                        availableHeight: INIT,
                        innerWidth: INIT,
                        innerHeight: INIT,
                        hasMultipleDisplays: INIT,
                    },
                    multimediaDevices: {
                        speakers: INIT,
                        microphones: INIT,
                        webcams: INIT,
                    },
                    mediaQueries: {
                        prefersColorScheme: INIT,
                        prefersReducedMotion: INIT,
                        prefersReducedTransparency: INIT,
                        colorGamut: INIT,
                        pointer: INIT,
                        anyPointer: INIT,
                        hover: INIT,
                        anyHover: INIT,
                        colorDepth: INIT,
                    },
                },
                // Browser identity & features
                browser: {
                    userAgent: INIT,
                    features: {
                        bitmask: INIT,
                        chrome: INIT,
                        brave: INIT,
                        applePaySupport: INIT,
                        opera: INIT,
                        serial: INIT,
                        attachShadow: INIT,
                        caches: INIT,
                        webAssembly: INIT,
                        buffer: INIT,
                        showModalDialog: INIT,
                    },
                    plugins: {
                        isValidPluginArray: INIT,
                        pluginCount: INIT,
                        pluginNamesHash: INIT,
                        pluginConsistency1: INIT,
                        pluginOverflow: INIT,
                    },
                    extensions: {
                        bitmask: INIT,
                        extensions: INIT,
                    },
                    highEntropyValues: {
                        architecture: INIT,
                        bitness: INIT,
                        brands: INIT,
                        mobile: INIT,
                        model: INIT,
                        platform: INIT,
                        platformVersion: INIT,
                        uaFullVersion: INIT,
                    },
                    etsl: INIT,
                    maths: INIT,
                    toSourceError: {
                        toSourceError: INIT,
                        hasToSource: INIT,
                    },
                },
                // Graphics & rendering
                graphics: {
                    webGL: {
                        vendor: INIT,
                        renderer: INIT,
                    },
                    webgpu: {
                        vendor: INIT,
                        architecture: INIT,
                        device: INIT,
                        description: INIT,
                    },
                    canvas: {
                        hasModifiedCanvas: INIT,
                        canvasFingerprint: INIT,
                    },
                },
                // Media codecs (at root level)
                codecs: {
                    audioCanPlayTypeHash: INIT,
                    videoCanPlayTypeHash: INIT,
                    audioMediaSourceHash: INIT,
                    videoMediaSourceHash: INIT,
                    rtcAudioCapabilitiesHash: INIT,
                    rtcVideoCapabilitiesHash: INIT,
                    hasMediaSource: INIT,
                },
                // Locale & internationalization
                locale: {
                    internationalization: {
                        timezone: INIT,
                        localeLanguage: INIT,
                    },
                    languages: {
                        languages: INIT,
                        language: INIT,
                    },
                },
                // Isolated execution contexts
                contexts: {
                    iframe: {
                        webdriver: INIT,
                        userAgent: INIT,
                        platform: INIT,
                        memory: INIT,
                        cpuCount: INIT,
                        language: INIT,
                    },
                    webWorker: {
                        webdriver: INIT,
                        userAgent: INIT,
                        platform: INIT,
                        memory: INIT,
                        cpuCount: INIT,
                        language: INIT,
                        vendor: INIT,
                        renderer: INIT,
                    },
                },
            },
            fsid: INIT,
            nonce: INIT,
            time: INIT,
            url: INIT,
            fastBotDetection: false,
            fastBotDetectionDetails: {
                headlessChromeScreenResolution: { detected: false, severity: 'high' },
                hasWebdriver: { detected: false, severity: 'high' },
                hasWebdriverWritable: { detected: false, severity: 'high' },
                hasSeleniumProperty: { detected: false, severity: 'high' },
                hasCDP: { detected: false, severity: 'high' },
                hasPlaywright: { detected: false, severity: 'high' },
                hasImpossibleDeviceMemory: { detected: false, severity: 'high' },
                hasHighCPUCount: { detected: false, severity: 'high' },
                hasMissingChromeObject: { detected: false, severity: 'high' },
                hasWebdriverIframe: { detected: false, severity: 'high' },
                hasWebdriverWorker: { detected: false, severity: 'high' },
                hasMismatchWebGLInWorker: { detected: false, severity: 'high' },
                hasMismatchPlatformIframe: { detected: false, severity: 'high' },
                hasMismatchPlatformWorker: { detected: false, severity: 'high' },
            },
        };
    }

    private async collectSignal(signal: () => any) {
        try {
            return await signal();
        } catch (e) {
            return ERROR;
        }
    }

    /**
     * Generate a JA4-inspired fingerprint scanner ID
     * Format: FS1_<det>_<auto>_<dev>_<brw>_<gfx>_<cod>_<loc>_<ctx>
     * 
     * Each section is delimited by '_', allowing partial matching.
     * Sections use the pattern: <bitmask>h<hash> where applicable.
     * Bitmasks are extensible - new boolean fields are appended without breaking existing positions.
     * 
     * Sections:
     * - det:  fastBotDetectionDetails bitmask (14 bits: headlessChromeScreenResolution, hasWebdriver, 
     *         hasWebdriverWritable, hasSeleniumProperty, hasCDP, hasPlaywright, hasImpossibleDeviceMemory,
     *         hasHighCPUCount, hasMissingChromeObject, hasWebdriverIframe, hasWebdriverWorker,
     *         hasMismatchWebGLInWorker, hasMismatchPlatformIframe, hasMismatchPlatformWorker)
     * - auto: automation bitmask (5 bits: webdriver, webdriverWritable, selenium, cdp, playwright) + hash
     * - dev:  WIDTHxHEIGHT + cpu + mem + device bitmask + hash of all device signals
     * - brw:  features.bitmask + extensions.bitmask + plugins bitmask (3 bits) + hash of browser signals
     * - gfx:  canvas bitmask (1 bit: hasModifiedCanvas) + hash of all graphics signals
     * - cod:  codecs bitmask (1 bit: hasMediaSource) + hash of all codec hashes
     * - loc:  language code (2 chars) + language count + hash of locale signals
     * - ctx:  context mismatch bitmask (2 bits: iframe, worker) + hash of all context signals
     */
    private generateFingerprintScannerId(): string {
        try {
            const s = this.fingerprint.signals;
            const det = this.fingerprint.fastBotDetectionDetails;

            // Section 1: Version
            const version = 'FS1';

            // Section 2: Detection bitmask - all 14 fastBotDetectionDetails booleans
            // Order matches FastBotDetectionDetails interface for consistency
            const detBitmask = [
                det.headlessChromeScreenResolution.detected,
                det.hasWebdriver.detected,
                det.hasWebdriverWritable.detected,
                det.hasSeleniumProperty.detected,
                det.hasCDP.detected,
                det.hasPlaywright.detected,
                det.hasImpossibleDeviceMemory.detected,
                det.hasHighCPUCount.detected,
                det.hasMissingChromeObject.detected,
                det.hasWebdriverIframe.detected,
                det.hasWebdriverWorker.detected,
                det.hasMismatchWebGLInWorker.detected,
                det.hasMismatchPlatformIframe.detected,
                det.hasMismatchPlatformWorker.detected,
            ].map(b => b ? '1' : '0').join('');
            const detSection = detBitmask;

            // Section 3: Automation - bitmask + hash of non-boolean fields
            const autoBitmask = [
                s.automation.webdriver === true,
                s.automation.webdriverWritable === true,
                s.automation.selenium === true,
                s.automation.cdp === true,
                s.automation.playwright === true,
            ].map(b => b ? '1' : '0').join('');
            const autoHash = hashCode(String(s.automation.navigatorPropertyDescriptors)).slice(0, 4);
            const autoSection = `${autoBitmask}h${autoHash}`;

            // Section 4: Device - screen dims + cpu + mem + bitmask + hash
            const width = typeof s.device.screenResolution.width === 'number' ? s.device.screenResolution.width : 0;
            const height = typeof s.device.screenResolution.height === 'number' ? s.device.screenResolution.height : 0;
            const cpu = typeof s.device.cpuCount === 'number' ? String(s.device.cpuCount).padStart(2, '0') : '00';
            const mem = typeof s.device.memory === 'number' ? String(Math.round(s.device.memory)).padStart(2, '0') : '00';
            const devBitmask = [
                s.device.screenResolution.hasMultipleDisplays === true,
                s.device.mediaQueries.prefersReducedMotion === true,
                s.device.mediaQueries.prefersReducedTransparency === true,
                s.device.mediaQueries.hover === true,
                s.device.mediaQueries.anyHover === true,
            ].map(b => b ? '1' : '0').join('');
            const devStr = [
                s.device.platform,
                s.device.screenResolution.pixelDepth,
                s.device.screenResolution.colorDepth,
                s.device.multimediaDevices.speakers,
                s.device.multimediaDevices.microphones,
                s.device.multimediaDevices.webcams,
                s.device.mediaQueries.prefersColorScheme,
                s.device.mediaQueries.colorGamut,
                s.device.mediaQueries.pointer,
                s.device.mediaQueries.anyPointer,
                s.device.mediaQueries.colorDepth,
            ].map(v => String(v)).join('|');
            const devHash = hashCode(devStr).slice(0, 6);
            const devSection = `${width}x${height}c${cpu}m${mem}b${devBitmask}h${devHash}`;

            // Section 5: Browser - use existing bitmasks + plugins bitmask + hash
            const featuresBitmask = typeof s.browser.features.bitmask === 'string' ? s.browser.features.bitmask : '0000000000';
            const extensionsBitmask = typeof s.browser.extensions.bitmask === 'string' ? s.browser.extensions.bitmask : '00000000';
            const pluginsBitmask = [
                s.browser.plugins.isValidPluginArray === true,
                s.browser.plugins.pluginConsistency1 === true,
                s.browser.plugins.pluginOverflow === true,
                s.browser.toSourceError.hasToSource === true,
            ].map(b => b ? '1' : '0').join('');
            const brwStr = [
                s.browser.userAgent,
                s.browser.etsl,
                s.browser.maths,
                s.browser.plugins.pluginCount,
                s.browser.plugins.pluginNamesHash,
                s.browser.toSourceError.toSourceError,
                s.browser.highEntropyValues.architecture,
                s.browser.highEntropyValues.bitness,
                s.browser.highEntropyValues.platform,
                s.browser.highEntropyValues.platformVersion,
                s.browser.highEntropyValues.uaFullVersion,
                s.browser.highEntropyValues.mobile,
            ].map(v => String(v)).join('|');
            const brwHash = hashCode(brwStr).slice(0, 6);
            const brwSection = `f${featuresBitmask}e${extensionsBitmask}p${pluginsBitmask}h${brwHash}`;

            // Section 6: Graphics - bitmask + hash
            const gfxBitmask = [
                s.graphics.canvas.hasModifiedCanvas === true,
            ].map(b => b ? '1' : '0').join('');
            const gfxStr = [
                s.graphics.webGL.vendor,
                s.graphics.webGL.renderer,
                s.graphics.webgpu.vendor,
                s.graphics.webgpu.architecture,
                s.graphics.webgpu.device,
                s.graphics.webgpu.description,
                s.graphics.canvas.canvasFingerprint,
            ].map(v => String(v)).join('|');
            const gfxHash = hashCode(gfxStr).slice(0, 6);
            const gfxSection = `${gfxBitmask}h${gfxHash}`;

            // Section 7: Codecs - bitmask + hash of all codec hashes
            const codBitmask = [
                s.codecs.hasMediaSource === true,
            ].map(b => b ? '1' : '0').join('');
            const codStr = [
                s.codecs.audioCanPlayTypeHash,
                s.codecs.videoCanPlayTypeHash,
                s.codecs.audioMediaSourceHash,
                s.codecs.videoMediaSourceHash,
                s.codecs.rtcAudioCapabilitiesHash,
                s.codecs.rtcVideoCapabilitiesHash,
            ].map(v => String(v)).join('|');
            const codHash = hashCode(codStr).slice(0, 6);
            const codSection = `${codBitmask}h${codHash}`;

            // Section 8: Locale - language code + count + hash
            const primaryLang = typeof s.locale.languages.language === 'string'
                ? s.locale.languages.language.slice(0, 2).toLowerCase()
                : 'xx';
            const langCount = Array.isArray(s.locale.languages.languages) ? s.locale.languages.languages.length : 0;
            const locStr = [
                s.locale.internationalization.timezone,
                s.locale.internationalization.localeLanguage,
                Array.isArray(s.locale.languages.languages) ? s.locale.languages.languages.join(',') : s.locale.languages.languages,
                s.locale.languages.language,
            ].map(v => String(v)).join('|');
            const locHash = hashCode(locStr).slice(0, 4);
            const locSection = `${primaryLang}${langCount}h${locHash}`;

            // Section 9: Contexts - mismatch bitmask + hash of all context signals
            const ctxBitmask = [
                hasContextMismatch(this.fingerprint, 'iframe'),
                hasContextMismatch(this.fingerprint, 'worker'),
                s.contexts.iframe.webdriver === true,
                s.contexts.webWorker.webdriver === true,
            ].map(b => b ? '1' : '0').join('');
            const ctxStr = [
                s.contexts.iframe.userAgent,
                s.contexts.iframe.platform,
                s.contexts.iframe.memory,
                s.contexts.iframe.cpuCount,
                s.contexts.iframe.language,
                s.contexts.webWorker.userAgent,
                s.contexts.webWorker.platform,
                s.contexts.webWorker.memory,
                s.contexts.webWorker.cpuCount,
                s.contexts.webWorker.language,
                s.contexts.webWorker.vendor,
                s.contexts.webWorker.renderer,
            ].map(v => String(v)).join('|');
            const ctxHash = hashCode(ctxStr).slice(0, 6);
            const ctxSection = `${ctxBitmask}h${ctxHash}`;

            return [
                version,
                detSection,
                autoSection,
                devSection,
                brwSection,
                gfxSection,
                codSection,
                locSection,
                ctxSection,
            ].join('_');
        } catch (e) {
            console.error('Error generating fingerprint scanner id', e);
            return ERROR;
        }
    }

    private async encryptFingerprint(fingerprint: string) {
        // Key is injected at build time via Vite's define option
        // Customers run: npx fpscanner build --key=their-key
        const key = __FP_ENCRYPTION_KEY__;
        const enc = await encryptString(JSON.stringify(fingerprint), key);

        return enc;
    }

    /**
     * Detection rules with name and severity.
     * All rules are currently HIGH severity as they indicate bot-like behavior.
     */
    private getDetectionRules(): DetectionRule[] {
        return [
            { name: 'headlessChromeScreenResolution', severity: HIGH, test: hasHeadlessChromeScreenResolution },
            { name: 'hasWebdriver', severity: HIGH, test: hasWebdriver },
            { name: 'hasWebdriverWritable', severity: HIGH, test: hasWebdriverWritable },
            { name: 'hasSeleniumProperty', severity: HIGH, test: hasSeleniumProperty },
            { name: 'hasCDP', severity: HIGH, test: hasCDP },
            { name: 'hasPlaywright', severity: HIGH, test: hasPlaywright },
            { name: 'hasImpossibleDeviceMemory', severity: HIGH, test: hasImpossibleDeviceMemory },
            { name: 'hasHighCPUCount', severity: HIGH, test: hasHighCPUCount },
            { name: 'hasMissingChromeObject', severity: HIGH, test: hasMissingChromeObject },
            { name: 'hasWebdriverIframe', severity: HIGH, test: hasWebdriverIframe },
            { name: 'hasWebdriverWorker', severity: HIGH, test: hasWebdriverWorker },
            { name: 'hasMismatchWebGLInWorker', severity: HIGH, test: hasMismatchWebGLInWorker },
            { name: 'hasMismatchPlatformIframe', severity: HIGH, test: hasMismatchPlatformIframe },
            { name: 'hasMismatchPlatformWorker', severity: HIGH, test: hasMismatchPlatformWorker },
            { name: 'hasSwiftshaderRenderer', severity: LOW, test: hasSwiftshaderRenderer },
            { name: 'hasUTCTimezone', severity: MEDIUM, test: hasUTCTimezone },
        ];
    }

    private runDetectionRules(): FastBotDetectionDetails {
        const rules = this.getDetectionRules();
        const results: FastBotDetectionDetails = {
            headlessChromeScreenResolution: { detected: false, severity: 'high' },
            hasWebdriver: { detected: false, severity: 'high' },
            hasWebdriverWritable: { detected: false, severity: 'high' },
            hasSeleniumProperty: { detected: false, severity: 'high' },
            hasCDP: { detected: false, severity: 'high' },
            hasPlaywright: { detected: false, severity: 'high' },
            hasImpossibleDeviceMemory: { detected: false, severity: 'high' },
            hasHighCPUCount: { detected: false, severity: 'high' },
            hasMissingChromeObject: { detected: false, severity: 'high' },
            hasWebdriverIframe: { detected: false, severity: 'high' },
            hasWebdriverWorker: { detected: false, severity: 'high' },
            hasMismatchWebGLInWorker: { detected: false, severity: 'high' },
            hasMismatchPlatformIframe: { detected: false, severity: 'high' },
            hasMismatchPlatformWorker: { detected: false, severity: 'high' },
        };

        for (const rule of rules) {
            try {
                const detected = rule.test(this.fingerprint);
                (results as any)[rule.name] = { detected, severity: rule.severity };
            } catch (e) {
                (results as any)[rule.name] = { detected: false, severity: rule.severity };
            }
        }

        return results;
    }

    async collectFingerprint(options: CollectFingerprintOptions = { encrypt: true }) {
        const { encrypt = true } = options;
        const s = this.fingerprint.signals;

        // Define all signal collection tasks to run in parallel
        const signalTasks = {
            // Automation signals
            webdriver: this.collectSignal(webdriver),
            webdriverWritable: this.collectSignal(webdriverWritable),
            selenium: this.collectSignal(hasSeleniumProperties),
            cdp: this.collectSignal(cdp),
            playwright: this.collectSignal(playwright),
            navigatorPropertyDescriptors: this.collectSignal(navigatorPropertyDescriptors),
            // Device signals
            cpuCount: this.collectSignal(cpuCount),
            memory: this.collectSignal(memory),
            platform: this.collectSignal(platform),
            screenResolution: this.collectSignal(screenResolution),
            multimediaDevices: this.collectSignal(multimediaDevices),
            mediaQueries: this.collectSignal(mediaQueries),
            // Browser signals
            userAgent: this.collectSignal(userAgent),
            browserFeatures: this.collectSignal(browserFeatures),
            plugins: this.collectSignal(plugins),
            browserExtensions: this.collectSignal(browserExtensions),
            highEntropyValues: this.collectSignal(highEntropyValues),
            etsl: this.collectSignal(etsl),
            maths: this.collectSignal(maths),
            toSourceError: this.collectSignal(toSourceError),
            // Graphics signals
            webGL: this.collectSignal(webGL),
            webgpu: this.collectSignal(webgpu),
            canvas: this.collectSignal(canvas),
            // Codecs
            mediaCodecs: this.collectSignal(mediaCodecs),
            // Locale signals
            internationalization: this.collectSignal(internationalization),
            languages: this.collectSignal(languages),
            // Context signals
            iframe: this.collectSignal(iframe),
            webWorker: this.collectSignal(worker),
            // Meta signals
            nonce: this.collectSignal(nonce),
            time: this.collectSignal(time),
            url: this.collectSignal(pageURL),
        };

        // Run all signal collections in parallel
        const keys = Object.keys(signalTasks) as (keyof typeof signalTasks)[];
        const results = await Promise.all(Object.values(signalTasks));
        const r = Object.fromEntries(keys.map((key, i) => [key, results[i]])) as Record<keyof typeof signalTasks, any>;

        // Assign results to fingerprint structure
        // Automation
        s.automation.webdriver = r.webdriver;
        s.automation.webdriverWritable = r.webdriverWritable;
        s.automation.selenium = r.selenium;
        s.automation.cdp = r.cdp;
        s.automation.playwright = r.playwright;
        s.automation.navigatorPropertyDescriptors = r.navigatorPropertyDescriptors;
        // Device
        s.device.cpuCount = r.cpuCount;
        s.device.memory = r.memory;
        s.device.platform = r.platform;
        s.device.screenResolution = r.screenResolution;
        s.device.multimediaDevices = r.multimediaDevices;
        s.device.mediaQueries = r.mediaQueries;
        // Browser
        s.browser.userAgent = r.userAgent;
        s.browser.features = r.browserFeatures;
        s.browser.plugins = r.plugins;
        s.browser.extensions = r.browserExtensions;
        s.browser.highEntropyValues = r.highEntropyValues;
        s.browser.etsl = r.etsl;
        s.browser.maths = r.maths;
        s.browser.toSourceError = r.toSourceError;
        // Graphics
        s.graphics.webGL = r.webGL;
        s.graphics.webgpu = r.webgpu;
        s.graphics.canvas = r.canvas;
        // Codecs
        s.codecs = r.mediaCodecs;
        // Locale
        s.locale.internationalization = r.internationalization;
        s.locale.languages = r.languages;
        // Contexts
        s.contexts.iframe = r.iframe;
        s.contexts.webWorker = r.webWorker;
        // Meta
        this.fingerprint.nonce = r.nonce;
        this.fingerprint.time = r.time;
        this.fingerprint.url = r.url;

        // Run detection rules (needed for fsid generation)
        this.fingerprint.fastBotDetectionDetails = this.runDetectionRules();
        
        // fastBotDetection = true if any detection rule was triggered
        this.fingerprint.fastBotDetection = Object.values(this.fingerprint.fastBotDetectionDetails)
            .some(result => result.detected);

        // Generate fsid after all signals and detections are collected
        this.fingerprint.fsid = this.generateFingerprintScannerId();
        console.log(this.fingerprint);

        if (encrypt) {
            const encryptedFingerprint = await this.encryptFingerprint(JSON.stringify(this.fingerprint));
            return encryptedFingerprint;
        }

        // Return the raw fingerprint if no encryption is requested
        return this.fingerprint;
    }
}

export default FingerprintScanner;
export * from './types';