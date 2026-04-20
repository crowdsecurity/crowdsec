import { Fingerprint } from "../types";

export function hasInconsistentEtsl(fingerprint: Fingerprint) {

    // On Chromium-based browsers, ETSL should be 33
    if (fingerprint.signals.browser.features.chrome && fingerprint.signals.browser.etsl !== 33) {
        return true;
    }

    // On Safari, ETSL should be 37
    if (fingerprint.signals.browser.features.safari && fingerprint.signals.browser.etsl !== 37) {
        return true;
    }

    // On Firefox, ETSL should be 37
    if (fingerprint.signals.browser.userAgent.includes('Firefox') && fingerprint.signals.browser.etsl !== 37) {
        return true;
    }

    return false;
}