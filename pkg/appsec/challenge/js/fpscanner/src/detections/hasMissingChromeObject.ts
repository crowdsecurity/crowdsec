import { Fingerprint } from "../types";

export function hasMissingChromeObject(fingerprint: Fingerprint) {
    const userAgent = fingerprint.signals.browser.userAgent;
    return fingerprint.signals.browser.features.chrome === false && typeof userAgent === 'string' && userAgent.includes('Chrome');
}