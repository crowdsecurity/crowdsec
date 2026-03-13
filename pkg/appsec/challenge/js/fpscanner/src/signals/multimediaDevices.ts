import { NA, setObjectValues } from "./utils";

export async function multimediaDevices() {
    return new Promise(async function (resolve) {
        var deviceToCount = {
            "audiooutput": 0,
            "audioinput": 0,
            "videoinput": 0
        };

        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
            const devices = await navigator.mediaDevices.enumerateDevices();
            if (typeof devices !== "undefined") {
                for (var i = 0; i < devices.length; i++) {
                    var name = devices[i].kind as keyof typeof deviceToCount;
                    deviceToCount[name] = deviceToCount[name] + 1;
                }

                return resolve({
                    speakers: deviceToCount.audiooutput,
                    microphones: deviceToCount.audioinput,
                    webcams: deviceToCount.videoinput
                });
            } else {
                setObjectValues(deviceToCount, NA);
                return resolve(deviceToCount);
            }

        } else {
            setObjectValues(deviceToCount, NA);
            return resolve(deviceToCount);
        }
    });
}