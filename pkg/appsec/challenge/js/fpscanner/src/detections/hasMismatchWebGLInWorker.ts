import { Fingerprint } from "../types";
import { ERROR, NA } from "../signals/utils";

export function hasMismatchWebGLInWorker(fingerprint: Fingerprint) {
    const worker = fingerprint.signals.contexts.webWorker;
    const webGL = fingerprint.signals.graphics.webGL;
    
    if (worker.vendor === ERROR || worker.renderer === ERROR || webGL.vendor === NA || webGL.renderer === NA) {
        return false;
    }

    return worker.vendor !== webGL.vendor || worker.renderer !== webGL.renderer;
}
