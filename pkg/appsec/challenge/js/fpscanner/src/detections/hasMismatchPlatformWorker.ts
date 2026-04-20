import { Fingerprint } from "../types";
import { ERROR, NA, SKIPPED } from "../signals/utils";

export function hasMismatchPlatformWorker(fingerprint: Fingerprint) {
    if (fingerprint.signals.contexts.webWorker.platform === NA || fingerprint.signals.contexts.webWorker.platform === ERROR || fingerprint.signals.contexts.webWorker.platform === SKIPPED) {
        return false;
    }

    return fingerprint.signals.device.platform !== fingerprint.signals.contexts.webWorker.platform;
}
