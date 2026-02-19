import { Fingerprint } from "../types";

export function hasSwiftshaderRenderer(fingerprint: Fingerprint) {
    return fingerprint.signals.graphics.webGL.renderer.includes('SwiftShader');
}
