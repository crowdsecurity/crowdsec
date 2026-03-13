import { Fingerprint } from "../types";

export function hasHighCPUCount(fingerprint: Fingerprint) {
    if (typeof fingerprint.signals.device.cpuCount !== 'number') {
        return false;
    }

    return fingerprint.signals.device.cpuCount > 70;
}