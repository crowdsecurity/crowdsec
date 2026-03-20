export function playwright() {
    return '__pwInitScripts' in window || '__playwright__binding__' in window;
}