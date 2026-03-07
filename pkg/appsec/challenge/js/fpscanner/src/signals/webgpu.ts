import { ERROR, INIT, NA, setObjectValues } from "./utils";

export async function webgpu() {
    const webGPUData = {
        vendor: INIT,
        architecture: INIT,
        device: INIT,
        description: INIT,
    };

    if ('gpu' in navigator) {
        try {
            const adapter = await (navigator as any).gpu.requestAdapter();
            if (adapter) {
                webGPUData.vendor = adapter.info.vendor;
                webGPUData.architecture = adapter.info.architecture;
                webGPUData.device = adapter.info.device;
                webGPUData.description = adapter.info.description;
            }
        } catch (e) {
            setObjectValues(webGPUData, ERROR);
        }
    } else {
        setObjectValues(webGPUData, NA);
    }

    return webGPUData;
}