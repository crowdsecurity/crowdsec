import { Fingerprint } from "../types";

export function hasMismatchLanguages(fingerprint: Fingerprint) {
    const languages = fingerprint.signals.locale.languages.languages;
    const language = fingerprint.signals.locale.languages.language;


    if (language && languages && Array.isArray(languages) && languages.length > 0) {
        return languages[0] !== language;
    }

    return false;
}