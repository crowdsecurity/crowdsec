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

  const result = JavaScriptObfuscator.obfuscate(
    sourceCode,
    JavaScriptObfuscator.getOptionsByPreset("low-obfuscation"),
  );

  writeStdout(result.getObfuscatedCode());
} catch (e) {
  writeStdout(`// OBFUSCATION FAILED: ${e.message}`);
}
