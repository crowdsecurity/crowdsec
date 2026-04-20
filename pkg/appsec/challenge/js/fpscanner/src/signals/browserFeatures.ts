import { INIT } from "./utils";

function safeCheck(check: () => boolean): boolean {
    try {
        return check();
    } catch {
        return false;
    }
}

export function browserFeatures() {
    const browserFeaturesData = {
        bitmask: INIT,
        chrome: safeCheck(() => 'chrome' in window),
        brave: safeCheck(() => 'brave' in navigator),
        applePaySupport: safeCheck(() => 'ApplePaySetup' in window),
        opera: safeCheck(() => (typeof (window as any).opr !== "undefined") || 
            (typeof (window as any).onoperadetachedviewchange === "object")),
        serial: safeCheck(() => (window.navigator as any).serial !== undefined),
        attachShadow: safeCheck(() => !!Element.prototype.attachShadow),
        caches: safeCheck(() => !!window.caches),
        webAssembly: safeCheck(() => !!window.WebAssembly && !!window.WebAssembly.instantiate),
        buffer: safeCheck(() => 'Buffer' in window),
        showModalDialog: safeCheck(() => 'showModalDialog' in window),
        safari: safeCheck(() => 'safari' in window),
        webkitPrefixedFunction: safeCheck(() => 'webkitCancelAnimationFrame' in window),
        mozPrefixedFunction: safeCheck(() => 'mozGetUserMedia' in navigator),
        usb: safeCheck(() => typeof (window as any).USB === 'function'),
        browserCapture: safeCheck(() => typeof (window as any).BrowserCaptureMediaStreamTrack === 'function'),
        paymentRequestUpdateEvent: safeCheck(() => typeof (window as any).PaymentRequestUpdateEvent === 'function'),
        pressureObserver: safeCheck(() => typeof (window as any).PressureObserver === 'function'),
        audioSession: safeCheck(() => 'audioSession' in navigator),
        selectAudioOutput: safeCheck(() => typeof navigator !== 'undefined' && typeof navigator.mediaDevices !== 'undefined' && typeof (navigator.mediaDevices as any).selectAudioOutput === 'function'),
        barcodeDetector: safeCheck(() => 'BarcodeDetector' in window),
        battery: safeCheck(() => 'getBattery' in navigator),
        devicePosture: safeCheck(() => 'DevicePosture' in window),
        documentPictureInPicture: safeCheck(() => 'documentPictureInPicture' in window),
        eyeDropper: safeCheck(() => 'EyeDropper' in window),
        editContext: safeCheck(() => 'EditContext' in window),
        fencedFrame: safeCheck(() => 'FencedFrameConfig' in window),
        sanitizer: safeCheck(() => 'Sanitizer' in window),
        otpCredential: safeCheck(() => 'OTPCredential' in window),
    };

    // set bitmask to 0/1 string based on browserFeaturesData, exclude bitmask property itself (you need to filter on the key)
    // use the filter function to exclude the bitmask property itself
    const bitmask = Object.keys(browserFeaturesData).filter((key) => key !== 'bitmask').map(key => (browserFeaturesData as any)[key] ? '1' : '0').join('');
    browserFeaturesData.bitmask = bitmask;
    return browserFeaturesData;
}