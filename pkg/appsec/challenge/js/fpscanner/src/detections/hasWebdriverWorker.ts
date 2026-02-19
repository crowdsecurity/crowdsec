import { Fingerprint } from "../types";

export function hasWebdriverWorker(fingerprint: Fingerprint) {
    return fingerprint.signals.contexts.webWorker.webdriver === true;
}
