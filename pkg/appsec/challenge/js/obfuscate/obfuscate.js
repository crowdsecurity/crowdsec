// Downloaded from https://cdn.jsdelivr.net/npm/javascript-obfuscator/dist/index.browser.js
import JavaScriptObfuscator from "./javascript-obfuscator.js";

function readStdin() {
  const buffer = new Uint8Array(1024);
  const input = [];
  while (true) {
    const bytesRead = Javy.IO.readSync(0, buffer);
    if (bytesRead === 0) break;
    const chunk = buffer.subarray(0, bytesRead);
    for (let i = 0; i < bytesRead; i++) {
      input.push(chunk[i]);
    }
  }
  return new TextDecoder().decode(new Uint8Array(input));
}

function writeStdout(str) {
  const buffer = new TextEncoder().encode(str);
  Javy.IO.writeSync(1, buffer);
}

try {
  const sourceCode = readStdin();

  // Spread the high-obfuscation preset, then add reservedStrings so the
  // sentinel that bridges the static bundle and the per-epoch dynamic key
  // module (CSEC_CHALLENGE_HOOK_v1) survives the string-array transform
  // identically in both bundles. Without this, the two independently-
  // obfuscated artifacts wouldn't agree on the globalThis symbol they
  // need to meet at.
  //
  // disableConsoleOutput is forced off because fpscanner's CDP detection
  // (signals/cdp.ts) relies on `console.log(err)` triggering DevTools'
  // eager access of `err.stack`, which in turn fires our overridden
  // `Error.prepareStackTrace`. The preset's default `true` rewrites the
  // call into a no-op stub and the detection silently always reports
  // false. Leave it off so the side-channel works.
  const opts = Object.assign(
    {},
    JavaScriptObfuscator.getOptionsByPreset("high-obfuscation"),
    {
      reservedStrings: ["__CSEC_CHALLENGE_HOOK_v1__"],
      disableConsoleOutput: false,
    },
  );

  const result = JavaScriptObfuscator.obfuscate(sourceCode, opts);

  writeStdout(result.getObfuscatedCode());
} catch (e) {
  writeStdout(`// OBFUSCATION FAILED: ${e.message}`);
}
