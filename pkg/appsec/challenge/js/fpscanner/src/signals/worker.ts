import { ERROR, INIT, setObjectValues } from './utils';

export async function worker() {
    return new Promise((resolve) => {
        const workerData = {
            vendor: INIT,
            renderer: INIT,
            userAgent: INIT,
            language: INIT,
            platform: INIT,
            memory: INIT,
            cpuCount: INIT,
        };

        try {
            const workerCode = `try {
                var fingerprintWorker = {};

                fingerprintWorker.userAgent = navigator.userAgent;
                fingerprintWorker.language = navigator.language;
                fingerprintWorker.cpuCount = navigator.hardwareConcurrency;
                fingerprintWorker.platform = navigator.platform;
                fingerprintWorker.memory = navigator.deviceMemory;
                

                var canvas = new OffscreenCanvas(1, 1);
                fingerprintWorker.vendor = 'INIT';
                fingerprintWorker.renderer = 'INIT';
                var gl = canvas.getContext('webgl');
                try {
                    if (gl) {
                        var glExt = gl.getExtension('WEBGL_debug_renderer_info');
                        fingerprintWorker.vendor = gl.getParameter(glExt.UNMASKED_VENDOR_WEBGL);
                        fingerprintWorker.renderer = gl.getParameter(glExt.UNMASKED_RENDERER_WEBGL);
                    } else {
                        fingerprintWorker.vendor = 'NA';
                        fingerprintWorker.renderer = 'NA';
                    }
                } catch (_) {
                    fingerprintWorker.vendor = 'ERROR';
                    fingerprintWorker.renderer = 'ERROR';
                }
                self.postMessage(fingerprintWorker);
            } catch (e) {
                self.postMessage(fingerprintWorker);
            }`

            
            const blob = new Blob([workerCode], { type: 'application/javascript' });
            const workerUrl = URL.createObjectURL(blob);
            const worker = new Worker(workerUrl);

            worker.onmessage = function (e) {
                try {
                    workerData.vendor = e.data.vendor;
                    workerData.renderer = e.data.renderer;
                    workerData.userAgent = e.data.userAgent;
                    workerData.language = e.data.language;
                    workerData.platform = e.data.platform;
                    workerData.memory = e.data.memory;
                    workerData.cpuCount = e.data.cpuCount;

                    return resolve(workerData);
                } catch (_) {
                    setObjectValues(workerData, ERROR);
                    return resolve(workerData);
                }
            }
        } catch (e) {
            setObjectValues(workerData, ERROR);

            return resolve(workerData);
        }

    });

}