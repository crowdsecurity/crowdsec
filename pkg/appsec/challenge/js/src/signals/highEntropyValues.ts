import { ERROR, INIT, NA, setObjectValues } from "./utils";

export async function highEntropyValues() {
    const navigator = window.navigator as any;
    const highEntropyValues = {
        architecture: INIT,
        bitness: INIT,
        brands: INIT,
        mobile: INIT,
        model: INIT,
        platform: INIT,
        platformVersion: INIT,
        uaFullVersion: INIT,
    };

    if ('userAgentData' in navigator) {
        try {
            const ua = await navigator.userAgentData.getHighEntropyValues([
                "architecture",
                "bitness",
                "brands",
                "mobile",
                "model",
                "platform",
                "platformVersion",
                "uaFullVersion"
            ]);

            highEntropyValues.architecture = ua.architecture;
            highEntropyValues.bitness = ua.bitness;
            highEntropyValues.brands = ua.brands;
            highEntropyValues.mobile = ua.mobile;
            highEntropyValues.model = ua.model;
            highEntropyValues.platform = ua.platform;
            highEntropyValues.platformVersion = ua.platformVersion;
            highEntropyValues.uaFullVersion = ua.uaFullVersion;


        } catch (e) {
            setObjectValues(highEntropyValues, ERROR);
        }

    } else {
        setObjectValues(highEntropyValues, NA);
    }

    return highEntropyValues;
}