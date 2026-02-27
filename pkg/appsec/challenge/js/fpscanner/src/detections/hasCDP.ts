import { Fingerprint } from "../types";

export function hasCDP(fingerprint: Fingerprint) {
    return fingerprint.signals.automation.cdp === true;
}