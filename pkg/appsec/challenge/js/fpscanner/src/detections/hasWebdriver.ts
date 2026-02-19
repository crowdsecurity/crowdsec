import { Fingerprint } from "../types";

export function hasWebdriver(fingerprint: Fingerprint) {
    return fingerprint.signals.automation.webdriver === true;
}