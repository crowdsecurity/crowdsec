export function webdriverWritable() {
    try {
        const prop = "webdriver";
        const navigator = window.navigator as any;
        if (!navigator[prop] && !navigator.hasOwnProperty(prop)) {
            navigator[prop] = 1;
            const writable = navigator[prop] === 1;
            delete navigator[prop];
            return writable;
        }
        return true;
    } catch (e) {
        return false;
    }
}