import { Fingerprint } from "../types";

// Not used as a detection rule since, more like an indicator
export function hasContextMismatch(fingerprint: Fingerprint, context: 'iframe' | 'worker'): boolean {
    const s = fingerprint.signals;
    if (context === 'iframe') {
        return s.contexts.iframe.webdriver !== s.automation.webdriver ||
               s.contexts.iframe.userAgent !== s.browser.userAgent ||
               s.contexts.iframe.platform !== s.device.platform ||
               s.contexts.iframe.memory !== s.device.memory ||
               s.contexts.iframe.cpuCount !== s.device.cpuCount;
    } else {
        return s.contexts.webWorker.webdriver !== s.automation.webdriver ||
               s.contexts.webWorker.userAgent !== s.browser.userAgent ||
               s.contexts.webWorker.platform !== s.device.platform ||
               s.contexts.webWorker.memory !== s.device.memory ||
               s.contexts.webWorker.cpuCount !== s.device.cpuCount;
    }
}