import FingerprintScanner from "/crowdsec-internal/challenge/challenge.js";

const scanner = new FingerprintScanner();
const result = await scanner.collectFingerprint({ encrypt: false });
console.log("Fingerprint result:", result);
fetch("/crowdsec-internal/challenge/submit", {
  // Send the fingerprint in a `fingerprint` field
  method: "POST",
  credentials: "same-origin",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: new URLSearchParams({ fingerprint: JSON.stringify(result) }),
})
  .then((response) => response.text())
  .then((data) => location.reload())
  .catch((error) => console.error("Error submitting fingerprint:", error));
