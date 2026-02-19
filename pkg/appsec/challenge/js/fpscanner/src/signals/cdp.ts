import { ERROR } from './utils';

export function cdp() {
    try {
        let wasAccessed = false;
        const originalPrepareStackTrace = (Error as any).prepareStackTrace;
        (Error as any).prepareStackTrace = function () {
            wasAccessed = true;
            return originalPrepareStackTrace;
        };
        const err = new Error('');
        console.log(err);

        return wasAccessed;
    } catch (e) {
        return ERROR;
    }
}