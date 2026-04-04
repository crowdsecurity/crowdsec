import { NA } from './utils';

export function screenResolution() {
    return {
        width: window.screen.width,
        height: window.screen.height,
        pixelDepth: window.screen.pixelDepth,
        colorDepth: window.screen.colorDepth,
        availableWidth: window.screen.availWidth,
        availableHeight: window.screen.availHeight,
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        hasMultipleDisplays: typeof (screen as any).isExtended !== 'undefined' ? (screen as any).isExtended : NA,
    };
}