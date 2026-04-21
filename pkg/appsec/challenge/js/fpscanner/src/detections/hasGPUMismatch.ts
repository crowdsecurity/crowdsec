import { Fingerprint } from "../types";

// For the moment, we only detect GPU mismatches related to Apple OS/GPU

export function hasGPUMismatch(fingerprint: Fingerprint) {
    const gpu = fingerprint.signals.graphics.webgpu;
    const webGL = fingerprint.signals.graphics.webGL;
    const userAgent = fingerprint.signals.browser.userAgent;


    // Inconsistencies around Apple OS/GPU
    if ((webGL.vendor.includes('Apple') || webGL.renderer.includes('Apple')) && !userAgent.includes('Mac')) {
        return true;
    }

    if (gpu.vendor.includes('apple') && !userAgent.includes('Mac')) {
        return true;
    }

    if (gpu.vendor.includes('apple') && !webGL.renderer.includes('Apple')) {
        return true;
    }
    
    return false;
}