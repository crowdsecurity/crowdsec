import { Fingerprint } from '../types';

export function hasHeadlessChromeScreenResolution(fingerprint: Fingerprint) {
    const screen = fingerprint.signals.device.screenResolution;

    return (screen.width === 800 && screen.height === 600) || (screen.availableWidth === 800 && screen.availableHeight === 600) || (screen.innerWidth === 800 && screen.innerHeight === 600);
}