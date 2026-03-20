import { Fingerprint } from "../types";

export function hasWebdriverWritable(fingerprint: Fingerprint) {
    return fingerprint.signals.automation.webdriverWritable === true;
}
