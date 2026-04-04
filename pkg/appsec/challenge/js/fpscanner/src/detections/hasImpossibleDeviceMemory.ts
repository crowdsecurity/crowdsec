import { Fingerprint } from "../types";

export function hasImpossibleDeviceMemory(fingerprint: Fingerprint) {
    if (typeof fingerprint.signals.device.memory !== 'number') {
        return false;
    }

    return (fingerprint.signals.device.memory > 8 || fingerprint.signals.device.memory < 0.25);
}