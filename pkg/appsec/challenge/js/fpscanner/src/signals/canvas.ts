import { ERROR, INIT, hashCode } from './utils';
import { SignalValue } from '../types';

async function hasModifiedCanvas(): Promise<SignalValue<boolean>> {
    return new Promise((resolve) => {

        try {
            const img = new Image();
            const ctx = document.createElement('canvas').getContext('2d') as CanvasRenderingContext2D;
            img.onload = () => {
                ctx.drawImage(img, 0, 0);
                resolve(ctx.getImageData(0, 0, 1, 1).data.filter(x => x === 0).length != 4);
            };

            img.onerror = () => {
                resolve(ERROR);
            };
            img.src = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQYV2NgAAIAAAUAAarVyFEAAAAASUVORK5CYII=';
        } catch (e) {
            resolve(ERROR);
        }
    });
}


function getCanvasFingerprint(): SignalValue<string> {
    var canvas = document.createElement('canvas');
    canvas.width = 400;
    canvas.height = 200;
    canvas.style.display = "inline";
    var context = canvas.getContext("2d") as CanvasRenderingContext2D;

    try {
        context.rect(0, 0, 10, 10);
        context.rect(2, 2, 6, 6);
        context.textBaseline = "alphabetic";
        context.fillStyle = "#f60";
        context.fillRect(125, 1, 62, 20);
        context.fillStyle = "#069";
        context.font = "11pt no-real-font-123";
        context.fillText("Cwm fjordbank glyphs vext quiz, 😃", 2, 15);
        context.fillStyle = "rgba(102, 204, 0, 0.2)";
        context.font = "18pt Arial";
        context.fillText("Cwm fjordbank glyphs vext quiz, 😃", 4, 45);

        context.globalCompositeOperation = "multiply";
        context.fillStyle = "rgb(255,0,255)";
        context.beginPath();
        context.arc(50, 50, 50, 0, 2 * Math.PI, !0);
        context.closePath();
        context.fill();
        context.fillStyle = "rgb(0,255,255)";
        context.beginPath();
        context.arc(100, 50, 50, 0, 2 * Math.PI, !0);
        context.closePath();
        context.fill();
        context.fillStyle = "rgb(255,255,0)";
        context.beginPath();
        context.arc(75, 100, 50, 0, 2 * Math.PI, !0);
        context.closePath();
        context.fill();
        context.fillStyle = "rgb(255,0,255)";
        context.arc(75, 75, 75, 0, 2 * Math.PI, !0);
        context.arc(75, 75, 25, 0, 2 * Math.PI, !0);
        context.fill("evenodd");
        return hashCode(canvas.toDataURL());

    } catch (e) {
        return ERROR;
    }
}

export async function canvas() {
    const canvasData = {
        hasModifiedCanvas: INIT as SignalValue<boolean>,
        canvasFingerprint: INIT as SignalValue<string>,
    };

    canvasData.hasModifiedCanvas = await hasModifiedCanvas();

    canvasData.canvasFingerprint = getCanvasFingerprint();

    return canvasData;
}