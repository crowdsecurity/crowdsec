import { ERROR, NA, hashCode, setObjectValues } from './utils';


const AUDIO_CODECS = [
    'audio/mp4; codecs="mp4a.40.2"',
    'audio/mpeg;',
    'audio/webm; codecs="vorbis"',
    'audio/ogg; codecs="vorbis"',
    'audio/wav; codecs="1"',
    'audio/ogg; codecs="speex"',
    'audio/ogg; codecs="flac"',
    'audio/3gpp; codecs="samr"',
];

const VIDEO_CODECS = [
    'video/mp4; codecs="avc1.42E01E, mp4a.40.2"',
    'video/mp4; codecs="avc1.42E01E"',
    'video/mp4; codecs="avc1.58A01E"',
    'video/mp4; codecs="avc1.4D401E"',
    'video/mp4; codecs="avc1.64001E"',
    'video/mp4; codecs="mp4v.20.8"',
    'video/mp4; codecs="mp4v.20.240"',
    'video/webm; codecs="vp8"',
    'video/ogg; codecs="theora"',
    'video/ogg; codecs="dirac"',
    'video/3gpp; codecs="mp4v.20.8"',
    'video/x-matroska; codecs="theora"',
];


function getCanPlayTypeSupport(codecs: string[], mediaType: 'audio' | 'video'): Record<string, string | null> {
    const result: Record<string, string | null> = {};
    try {
        const element = document.createElement(mediaType);
        for (const codec of codecs) {
            try {
                result[codec] = element.canPlayType(codec) || null;
            } catch {
                result[codec] = null;
            }
        }
    } catch {
        for (const codec of codecs) {
            result[codec] = null;
        }
    }
    return result;
}

function getMediaSourceSupport(codecs: string[]): Record<string, boolean | null> {
    const result: Record<string, boolean | null> = {};
    const MediaSource = window.MediaSource;
    
    if (!MediaSource || typeof MediaSource.isTypeSupported !== 'function') {
        for (const codec of codecs) {
            result[codec] = null;
        }
        return result;
    }
    
    for (const codec of codecs) {
        try {
            result[codec] = MediaSource.isTypeSupported(codec);
        } catch {
            result[codec] = null;
        }
    }
    return result;
}

function getRtcCapabilities(kind: 'audio' | 'video'): string | typeof NA | typeof ERROR {
    try {
        const RTCRtpReceiver = window.RTCRtpReceiver;
        if (RTCRtpReceiver && typeof RTCRtpReceiver.getCapabilities === 'function') {
            const capabilities = RTCRtpReceiver.getCapabilities(kind);
            return hashCode(JSON.stringify(capabilities));
        }
        return NA;
    } catch (e) {
        return ERROR;
    }
}

export function mediaCodecs() {
    const mediaCodecsData = {
        audioCanPlayTypeHash: NA as string | typeof NA | typeof ERROR,
        videoCanPlayTypeHash: NA as string | typeof NA | typeof ERROR,
        audioMediaSourceHash: NA as string | typeof NA | typeof ERROR,
        videoMediaSourceHash: NA as string | typeof NA | typeof ERROR,
        rtcAudioCapabilitiesHash: NA as string | typeof NA | typeof ERROR,
        rtcVideoCapabilitiesHash: NA as string | typeof NA | typeof ERROR,
        hasMediaSource: false,
    };

    try {
        // Check MediaSource availability
        mediaCodecsData.hasMediaSource = !!window.MediaSource;

        // canPlayType support - hash the results
        const audioCanPlayType = getCanPlayTypeSupport(AUDIO_CODECS, 'audio');
        const videoCanPlayType = getCanPlayTypeSupport(VIDEO_CODECS, 'video');
        mediaCodecsData.audioCanPlayTypeHash = hashCode(JSON.stringify(audioCanPlayType));
        mediaCodecsData.videoCanPlayTypeHash = hashCode(JSON.stringify(videoCanPlayType));

        // MediaSource.isTypeSupported - hash the results
        const audioMediaSource = getMediaSourceSupport(AUDIO_CODECS);
        const videoMediaSource = getMediaSourceSupport(VIDEO_CODECS);
        mediaCodecsData.audioMediaSourceHash = hashCode(JSON.stringify(audioMediaSource));
        mediaCodecsData.videoMediaSourceHash = hashCode(JSON.stringify(videoMediaSource));

        // RTCRtpReceiver.getCapabilities - already returns hash
        mediaCodecsData.rtcAudioCapabilitiesHash = getRtcCapabilities('audio');
        mediaCodecsData.rtcVideoCapabilitiesHash = getRtcCapabilities('video');

    } catch (e) {
        setObjectValues(mediaCodecsData, ERROR);
    }

    return mediaCodecsData;
}
