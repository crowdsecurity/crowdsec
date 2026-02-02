import { ERROR, INIT, NA } from './utils';

export function webGL() {
    const webGLData = {
        vendor: INIT,
        renderer: INIT,
    };

    try {
        var canvas = document.createElement('canvas');
        var ctx = (canvas.getContext("webgl") || canvas.getContext("experimental-webgl")) as any;
        if (ctx.getSupportedExtensions().indexOf("WEBGL_debug_renderer_info") >= 0) {
            webGLData.vendor = ctx.getParameter(ctx.getExtension('WEBGL_debug_renderer_info').UNMASKED_VENDOR_WEBGL);
            webGLData.renderer = ctx.getParameter(ctx.getExtension('WEBGL_debug_renderer_info').UNMASKED_RENDERER_WEBGL);
        } else {
            webGLData.vendor = NA;
            webGLData.renderer = NA;
        }
    } catch (e) {
        webGLData.vendor = ERROR;
        webGLData.renderer = ERROR;
    }

    return webGLData;
}