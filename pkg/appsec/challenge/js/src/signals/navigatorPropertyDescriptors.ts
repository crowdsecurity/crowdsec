export function navigatorPropertyDescriptors() {
    const properties = ['deviceMemory', 'hardwareConcurrency', 'language', 'languages', 'platform'];

    const results = [];

    for (const property of properties) {
        const res = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(navigator), property);

        if (res && res.value) {
            results.push('1');
        } else {
            results.push('0');
        }
    }

    return results.join('');
}