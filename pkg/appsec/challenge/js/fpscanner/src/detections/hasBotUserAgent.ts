import { Fingerprint } from "../types";

export function hasBotUserAgent(fingerprint: Fingerprint) {
    const userAgents = [
        fingerprint.signals.browser.userAgent,
        fingerprint.signals.contexts.iframe.userAgent,
        fingerprint.signals.contexts.webWorker.userAgent,
    ];

    return userAgents.some(userAgent => /bot|headless/i.test(userAgent.toLowerCase()));
}