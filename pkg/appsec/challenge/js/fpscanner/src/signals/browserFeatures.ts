import { INIT } from "./utils";

export function browserFeatures() {
    const browserFeaturesData = {
        bitmask: INIT,
        chrome: 'chrome' in window,
        brave: 'brave' in navigator,
        applePaySupport: 'ApplePaySetup' in window,
        opera: (typeof (window as any).opr !== "undefined") || 
        (typeof (window as any).onoperadetachedviewchange === "object"),
        serial: (window.navigator as any).serial !== undefined,
        attachShadow: !!Element.prototype.attachShadow,
        caches: !!window.caches,
        webAssembly: !!window.WebAssembly && !!window.WebAssembly.instantiate,
        buffer: 'Buffer' in window,
        showModalDialog: 'showModalDialog' in window,
    };

    // set bitmask to 0/1 string based on browserFeaturesData, exclude bitmask property itself (you need to filter on the key)
    // use the filter function to exclude the bitmask property itself
    const bitmask = Object.keys(browserFeaturesData).filter((key) => key !== 'bitmask').map(key => (browserFeaturesData as any)[key] ? '1' : '0').join('');
    browserFeaturesData.bitmask = bitmask;
    return browserFeaturesData;
}