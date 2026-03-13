import { INIT } from './utils';

export function toSourceError() {
    const toSourceErrorData = {
        toSourceError: INIT,
        hasToSource: false,
    };

    try {
        (null as any).usdfsh;
    } catch (e) {
        toSourceErrorData.toSourceError = (e as Error).toString();
    }

    try {
        throw "xyz";
    } catch (e: any) {
        try {
            e.toSource();
            toSourceErrorData.hasToSource = true;
        } catch (e2) {
            toSourceErrorData.hasToSource = false;
        }
    }

    return toSourceErrorData;
}