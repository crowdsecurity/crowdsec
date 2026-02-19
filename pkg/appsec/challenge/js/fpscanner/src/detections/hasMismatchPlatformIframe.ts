import { Fingerprint } from "../types";
import { ERROR, NA } from "../signals/utils";

export function hasMismatchPlatformIframe(fingerprint: Fingerprint) {
    if (fingerprint.signals.contexts.iframe.platform === NA || fingerprint.signals.contexts.iframe.platform === ERROR) {
        return false;
    }

    return fingerprint.signals.device.platform !== fingerprint.signals.contexts.iframe.platform;
}
