import { ERROR, INIT, setObjectValues } from './utils';

export function mediaQueries() {
    const mediaQueriesData = {
        prefersColorScheme: INIT as string | null | typeof INIT | typeof ERROR,
        prefersReducedMotion: INIT as boolean | typeof INIT | typeof ERROR,
        prefersReducedTransparency: INIT as boolean | typeof INIT | typeof ERROR,
        colorGamut: INIT as string | null | typeof INIT | typeof ERROR,
        pointer: INIT as string | null | typeof INIT | typeof ERROR,
        anyPointer: INIT as string | null | typeof INIT | typeof ERROR,
        hover: INIT as boolean | typeof INIT | typeof ERROR,
        anyHover: INIT as boolean | typeof INIT | typeof ERROR,
        colorDepth: INIT as number | typeof INIT | typeof ERROR,
    };

    try {
        // Prefers color scheme
        if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
            mediaQueriesData.prefersColorScheme = 'dark';
        } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
            mediaQueriesData.prefersColorScheme = 'light';
        } else {
            mediaQueriesData.prefersColorScheme = null;
        }

        // Prefers reduced motion
        mediaQueriesData.prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        // Prefers reduced transparency
        mediaQueriesData.prefersReducedTransparency = window.matchMedia('(prefers-reduced-transparency: reduce)').matches;

        // Color gamut
        if (window.matchMedia('(color-gamut: rec2020)').matches) {
            mediaQueriesData.colorGamut = 'rec2020';
        } else if (window.matchMedia('(color-gamut: p3)').matches) {
            mediaQueriesData.colorGamut = 'p3';
        } else if (window.matchMedia('(color-gamut: srgb)').matches) {
            mediaQueriesData.colorGamut = 'srgb';
        } else {
            mediaQueriesData.colorGamut = null;
        }

        // Pointer
        if (window.matchMedia('(pointer: fine)').matches) {
            mediaQueriesData.pointer = 'fine';
        } else if (window.matchMedia('(pointer: coarse)').matches) {
            mediaQueriesData.pointer = 'coarse';
        } else if (window.matchMedia('(pointer: none)').matches) {
            mediaQueriesData.pointer = 'none';
        } else {
            mediaQueriesData.pointer = null;
        }

        // Any pointer
        if (window.matchMedia('(any-pointer: fine)').matches) {
            mediaQueriesData.anyPointer = 'fine';
        } else if (window.matchMedia('(any-pointer: coarse)').matches) {
            mediaQueriesData.anyPointer = 'coarse';
        } else if (window.matchMedia('(any-pointer: none)').matches) {
            mediaQueriesData.anyPointer = 'none';
        } else {
            mediaQueriesData.anyPointer = null;
        }

        // Hover
        mediaQueriesData.hover = window.matchMedia('(hover: hover)').matches;

        // Any hover
        mediaQueriesData.anyHover = window.matchMedia('(any-hover: hover)').matches;

        // Color depth - find the maximum supported color depth
        let maxColorDepth = 0;
        for (let c = 0; c <= 16; c++) {
            if (window.matchMedia(`(color: ${c})`).matches) {
                maxColorDepth = c;
            }
        }
        mediaQueriesData.colorDepth = maxColorDepth;

    } catch (e) {
        setObjectValues(mediaQueriesData, ERROR);
    }

    return mediaQueriesData;
}
