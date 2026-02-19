import { Fingerprint } from '../types';

export function hasHeadlessChromeScreenResolution(fingerprint: Fingerprint) {
    const screen = fingerprint.signals.device.screenResolution;
    if (typeof screen.width !== 'number' || typeof screen.height !== 'number') {
        return false;
    }

    return (screen.width === 600 && screen.height === 800) || (screen.availableWidth === 600 && screen.availableHeight === 800) || (screen.innerWidth === 600 && screen.innerHeight === 800);
}