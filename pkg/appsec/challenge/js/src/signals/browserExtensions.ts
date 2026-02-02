import { INIT } from "./utils";

export function browserExtensions() {
    const browserExtensionsData = {
        bitmask: INIT,
        extensions: [] as string[],
    };

    const hasGrammarly = document.body.hasAttribute('data-gr-ext-installed');
    const hasMetamask = typeof (window as any).ethereum !=='undefined';
    const hasCouponBirds = document.getElementById('coupon-birds-drop-div') !== null;
    const hasDeepL = document.querySelector('deepl-input-controller') !== null;
    const hasMonicaAI = document.getElementById('monica-content-root') !== null;
    const hasSiderAI = document.querySelector('chatgpt-sidebar') !== null;
    const hasRequestly = typeof (window as any).__REQUESTLY__ !== 'undefined';
    const hasVeepn = Array.from(document.querySelectorAll('*'))
    .filter(el => el.tagName.toLowerCase().startsWith('veepn-')).length > 0;

    browserExtensionsData.bitmask = [
        hasGrammarly ? '1' : '0',
        hasMetamask ? '1' : '0',
        hasCouponBirds ? '1' : '0',
        hasDeepL ? '1' : '0',
        hasMonicaAI ? '1' : '0',
        hasSiderAI ? '1' : '0',
        hasRequestly ? '1' : '0',
        hasVeepn ? '1' : '0',
    ].join('');


    if (hasGrammarly) {
        browserExtensionsData.extensions.push('grammarly');
    }
    if (hasMetamask) {
        browserExtensionsData.extensions.push('metamask');
    }
    if (hasCouponBirds) {
        browserExtensionsData.extensions.push('coupon-birds');
    }
    if (hasDeepL) {
        browserExtensionsData.extensions.push('deepl');
    }
    if (hasMonicaAI) {
        browserExtensionsData.extensions.push('monica-ai');
    }
    if (hasSiderAI) {
        browserExtensionsData.extensions.push('sider-ai');
    }
    if (hasRequestly) {
        browserExtensionsData.extensions.push('requestly');
    }
    if (hasVeepn) {
        browserExtensionsData.extensions.push('veepn');
    }
    
    return browserExtensionsData;
}