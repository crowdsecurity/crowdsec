import { Fingerprint } from "../types";

export function hasWebdriverIframe(fingerprint: Fingerprint) {
    return fingerprint.signals.contexts.iframe.webdriver === true;
}
