import { Fingerprint } from "../types";

export function hasSeleniumProperty(fingerprint: Fingerprint) {
    return !!fingerprint.signals.automation.selenium;
}
