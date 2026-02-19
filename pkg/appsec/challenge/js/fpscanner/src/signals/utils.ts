export const ERROR = 'ERROR';
export const INIT = 'INIT';
export const NA = 'NA';
export const HIGH = 'high'
export const LOW = 'low'
export const MEDIUM = 'medium'


export function hashCode(str: string) {
    let hash = 0;
    for (let i = 0, len = str.length; i < len; i++) {
        let chr = str.charCodeAt(i);
        hash = (hash << 5) - hash + chr;
        hash |= 0;
    }
    return hash.toString(16).padStart(8, "0");
}

export function setObjectValues(object: any, value: any) {
    for (const key in object) {
        object[key] = value;
    }
}
