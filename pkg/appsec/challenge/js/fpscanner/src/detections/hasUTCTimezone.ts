import { Fingerprint } from "../types";

export function hasUTCTimezone(fingerprint: Fingerprint) {
    return fingerprint.signals.locale.internationalization.timezone === 'UTC';
}