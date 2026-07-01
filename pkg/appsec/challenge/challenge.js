// --- Pure JS SHA-256 (RFC 6234) ---

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256(data) {
  let h0 = 0x6a09e667,
    h1 = 0xbb67ae85,
    h2 = 0x3c6ef372,
    h3 = 0xa54ff53a,
    h4 = 0x510e527f,
    h5 = 0x9b05688c,
    h6 = 0x1f83d9ab,
    h7 = 0x5be0cd19;

  const len = data.length;
  const bitLen = len * 8;

  const padLen = 64 - ((len + 9) % 64);
  const totalLen = len + 1 + (padLen === 64 ? 0 : padLen) + 8;
  const msg = new Uint8Array(totalLen);
  msg.set(data);
  msg[len] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(totalLen - 4, bitLen, false);

  const w = new Int32Array(64);
  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = dv.getInt32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 =
        (((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^
          ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^
          (w[i - 15] >>> 3)) |
        0;
      const s1 =
        (((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^
          ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^
          (w[i - 2] >>> 10)) |
        0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4,
      f = h5,
      g = h6,
      h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 =
        (((e >>> 6) | (e << 26)) ^
          ((e >>> 11) | (e << 21)) ^
          ((e >>> 25) | (e << 7))) |
        0;
      const ch = ((e & f) ^ (~e & g)) | 0;
      const temp1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 =
        (((a >>> 2) | (a << 30)) ^
          ((a >>> 13) | (a << 19)) ^
          ((a >>> 22) | (a << 10))) |
        0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) | 0;
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
    h5 = (h5 + f) | 0;
    h6 = (h6 + g) | 0;
    h7 = (h7 + h) | 0;
  }

  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, h0, false);
  ov.setUint32(4, h1, false);
  ov.setUint32(8, h2, false);
  ov.setUint32(12, h3, false);
  ov.setUint32(16, h4, false);
  ov.setUint32(20, h5, false);
  ov.setUint32(24, h6, false);
  ov.setUint32(28, h7, false);
  return out;
}

// --- Helpers ---

function toHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] >> 4).toString(16) + (bytes[i] & 0xf).toString(16);
  }
  return hex;
}

function encode(str) {
  return new TextEncoder().encode(str);
}

function sha256Hex(str) {
  return toHex(sha256(encode(str)));
}

// --- HMAC-SHA256 ---

function hmacSHA256(key, message) {
  if (key.length > 64) {
    key = sha256(key);
  }
  const paddedKey = new Uint8Array(64);
  paddedKey.set(key);

  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  const inner = new Uint8Array(64 + message.length);
  inner.set(ipad);
  inner.set(message, 64);
  const innerHash = sha256(inner);

  const outer = new Uint8Array(64 + 32);
  outer.set(opad);
  outer.set(innerHash, 64);
  return sha256(outer);
}

function hmacSHA256Hex(keyStr, msgStr) {
  return toHex(hmacSHA256(encode(keyStr), encode(msgStr)));
}

// hexToBytes decodes a hex string into a Uint8Array. Used to materialize the
// per-epoch HMAC key delivered as hex by the dynamic module.
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function hmacSHA256HexKey(keyHex, msgStr) {
  return toHex(hmacSHA256(hexToBytes(keyHex), encode(msgStr)));
}

// --- Proof-of-Work (offloaded to Web Worker) ---

const powWorkerPath = "__CROWDSEC_POW_WORKER_PATH__";

function solvePoWAsync(prefix, difficulty) {
  if (difficulty <= 0) {
    return Promise.resolve("0");
  }

  try {
    const worker = new Worker(powWorkerPath);

    return new Promise((resolve) => {
      worker.onmessage = (e) => {
        worker.terminate();
        resolve(e.data);
      };
      worker.onerror = () => {
        worker.terminate();
        resolve(solvePoWMainThread(prefix, difficulty));
      };
      worker.postMessage({ p: prefix, d: difficulty });
    });
  } catch (_) {
    return Promise.resolve(solvePoWMainThread(prefix, difficulty));
  }
}

function solvePoWMainThread(prefix, difficulty) {
  let nonce = 0;
  while (true) {
    const candidate = prefix + nonce.toString(36);
    const hash = sha256(encode(candidate));
    const fullBytes = difficulty >> 3;
    const remainBits = difficulty & 7;
    let ok = true;
    for (let i = 0; i < fullBytes; i++) {
      if (hash[i] !== 0) {
        ok = false;
        break;
      }
    }
    if (ok && remainBits > 0) {
      const mask = (0xff << (8 - remainBits)) & 0xff;
      if ((hash[fullBytes] & mask) !== 0) ok = false;
    }
    if (ok) return nonce.toString(36);
    nonce++;
  }
}

// --- Fingerprint encryption (XOR) ---

function encryptFingerprint(key, fingerprint) {
  const keyBytes = encode(key);
  const textBytes = encode(fingerprint);
  const encrypted = new Uint8Array(textBytes.length);

  for (let i = 0; i < textBytes.length; i++) {
    encrypted[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
  }

  const binaryString = String.fromCharCode(...encrypted);
  return btoa(binaryString);
}

// --- Non-secret per-request values (plain template injection) ---
//
// Set on `globalThis` by a plain <script> the server renders before this
// module. None are secret:
//   _ts   — server time (forgeable but freshness-windowed)
//   _powP — random PoW salt (server-issued so clients can't pick easy salts)
//   _powM — HMAC(_powP, _r, _ts) under the per-epoch key
//   _powD — PoW difficulty
//   _r    — per-challenge nonce; seeds s = HMAC(K, r)
// The secret is the per-epoch K, delivered only by the dynamic key module; the
// derived s is never transmitted.

const ts = typeof _ts !== "undefined" ? _ts : "";
const powPrefix = typeof _powP !== "undefined" ? _powP : "";
const powMAC = typeof _powM !== "undefined" ? _powM : "";
const powDifficulty = typeof _powD !== "undefined" ? _powD : 12;
const r = typeof _r !== "undefined" ? _r : "";
const submitPath = "__CROWDSEC_SUBMIT_PATH__";

// --- Challenge status reporting ---

function reportChallengeStatus(status) {
  if (typeof window.crowdsecSetChallengeStatus === "function") {
    window.crowdsecSetChallengeStatus(status);
    return;
  }

  window.dispatchEvent(
    new CustomEvent("crowdsec-challenge-status", {
      detail: { status },
    }),
  );
}

// --- Main flow ---
// The static bundle registers a hook on globalThis; the dynamic key module
// (loaded after) calls it with { key, epoch }. Key-dependent crypto lives here;
// the static bundle holds no hardcoded K. The hook name survives obfuscation
// via `reservedStrings` so both bundles meet on the same global.

const CSEC_HOOK_NAME = "__CSEC_CHALLENGE_HOOK_v1__";

async function runChallenge(epochKey) {
  // Fail closed if the fpscanner bundle didn't load.
  const Scanner = globalThis.CrowdsecFingerprintScanner;
  if (typeof Scanner !== "function") {
    reportChallengeStatus("fail");
    return;
  }

  const [nonce, fpResult] = await Promise.all([
    solvePoWAsync(powPrefix, powDifficulty),
    new Scanner().collectFingerprint({ encrypt: false }),
  ]);

  // Per-challenge secret s = HMAC(K_epoch, r). Never transmitted; the server
  // derives the same s from its per-epoch key and the cleartext r. epochKey is
  // hex-encoded K; HMAC over its raw bytes.
  const s = hmacSHA256HexKey(epochKey, r);

  // Fingerprint payload obfuscation key, derived from the secret s (NOT a
  // confidentiality guarantee — light obfuscation only).
  const encKey = hmacSHA256Hex(s, "fpenc" + r);
  const f = encryptFingerprint(encKey, JSON.stringify(fpResult));

  // Submission signature binds (r, ts, nonce, f) under the secret s.
  const sig = hmacSHA256Hex(s, r + ts + nonce + f);

  return fetch(submitPath, {
    method: "POST",
    credentials: "same-origin",
    body: new URLSearchParams({
      f: f,
      r: r,
      ts: ts,
      sig: sig,
      n: nonce,
      p: powPrefix,
      m: powMAC,
      d: powDifficulty,
      u: window.location.pathname,
    }),
  })
    .then((response) => response.json())
    .then((data) => {
      const status = typeof data?.status === "string" ? data.status : "fail";
      reportChallengeStatus(status);
    })
    .catch(() => {
      reportChallengeStatus("fail");
    });
}

// Register the hook. The dynamic module (loaded after this) reads the same
// CSEC_HOOK_NAME string and invokes runChallenge with the per-epoch key.
globalThis[CSEC_HOOK_NAME] = function (params) {
  // Defensive: the dynamic module must pass a non-empty string key.
  if (!params || typeof params.key !== "string" || params.key.length === 0) {
    reportChallengeStatus("fail");
    return;
  }
  runChallenge(params.key);
};
