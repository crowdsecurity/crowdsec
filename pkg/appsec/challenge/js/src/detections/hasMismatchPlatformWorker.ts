import { Fingerprint } from "../types";
import { ERROR, NA } from "../signals/utils";

export function hasMismatchPlatformWorker(fingerprint: Fingerprint) {
    if (fingerprint.signals.contexts.webWorker.platform === NA || fingerprint.signals.contexts.webWorker.platform === ERROR) {
        return false;
    }

    return fingerprint.signals.device.platform !== fingerprint.signals.contexts.webWorker.platform;
}
