import FingerprintScanner from "/crowdsec-internal/challenge/challenge.js";

async function getSessionKey(ticket) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(ticket),
  );
  const hashArray = Array.from(new Uint8Array(hash));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hashHex;
}

async function generateHMAC(key, message) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(message);

  const k = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign("HMAC", k, messageData);
  const signatureArray = Array.from(new Uint8Array(signature));
  const signatureHex = signatureArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return signatureHex;
}

async function encryptFingerprint(key, fingerprint) {
  const keyBytes = new TextEncoder().encode(key);
  const textBytes = new TextEncoder().encode(fingerprint);
  const encrypted = new Uint8Array(textBytes.length);

  for (let i = 0; i < textBytes.length; i++) {
    encrypted[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
  }

  // Convert to base64 for safe string representation
  const binaryString = String.fromCharCode(...encrypted);
  return btoa(binaryString);
}

const ts = "{{.Timestamp}}";
const ticket = "{{.Ticket}}";

await new Promise((r) => setTimeout(r, 4000));
const scanner = new FingerprintScanner();
const result = await scanner.collectFingerprint({ encrypt: false });
const sessionKey = await getSessionKey(ticket);
const f = await encryptFingerprint(sessionKey, JSON.stringify(result));
const h = await generateHMAC(sessionKey, f + ts + ticket);
fetch("/crowdsec-internal/challenge/submit", {
  method: "POST",
  credentials: "same-origin",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: new URLSearchParams({ f: f, t: ticket, ts: ts, h: h, s: sessionKey }),
})
  .then((response) => response.json())
  .then((data) => console.log(data))
  .catch((error) => console.error("Error submitting fingerprint:", error));
