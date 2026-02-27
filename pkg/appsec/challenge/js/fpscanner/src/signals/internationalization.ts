import { INIT, ERROR, NA } from "./utils";

export function internationalization() {
    const internationalizationData = {
        timezone: INIT,
        localeLanguage: INIT,
    };

    try {
        if (typeof Intl !== 'undefined' && typeof Intl.DateTimeFormat !== 'undefined') {
            const dtfOptions = Intl.DateTimeFormat().resolvedOptions();
            internationalizationData.timezone = dtfOptions.timeZone;
            internationalizationData.localeLanguage = dtfOptions.locale;
        } else {
            internationalizationData.timezone = NA;
            internationalizationData.localeLanguage = NA;
        }
    } catch (e) {
        internationalizationData.timezone = ERROR;
        internationalizationData.localeLanguage = ERROR;
    }

    return internationalizationData;
}