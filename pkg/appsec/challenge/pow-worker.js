"use strict";

var K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function sha256(data) {
  var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
      h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  var len = data.length, bitLen = len * 8;
  var padLen = 64 - ((len + 9) % 64);
  var totalLen = len + 1 + (padLen === 64 ? 0 : padLen) + 8;
  var msg = new Uint8Array(totalLen);
  msg.set(data); msg[len] = 0x80;
  var dv = new DataView(msg.buffer);
  dv.setUint32(totalLen - 4, bitLen, false);
  var w = new Int32Array(64);
  for (var offset = 0; offset < totalLen; offset += 64) {
    for (var i = 0; i < 16; i++) w[i] = dv.getInt32(offset + i * 4, false);
    for (var i = 16; i < 64; i++) {
      var s0 = (((w[i-15] >>> 7) | (w[i-15] << 25)) ^ ((w[i-15] >>> 18) | (w[i-15] << 14)) ^ (w[i-15] >>> 3)) | 0;
      var s1 = (((w[i-2] >>> 17) | (w[i-2] << 15)) ^ ((w[i-2] >>> 19) | (w[i-2] << 13)) ^ (w[i-2] >>> 10)) | 0;
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (var i = 0; i < 64; i++) {
      var S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) | 0;
      var ch = ((e & f) ^ (~e & g)) | 0;
      var t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      var S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) | 0;
      var maj = ((a & b) ^ (a & c) ^ (b & c)) | 0;
      var t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  var out = new Uint8Array(32);
  var ov = new DataView(out.buffer);
  ov.setUint32(0, h0, false); ov.setUint32(4, h1, false);
  ov.setUint32(8, h2, false); ov.setUint32(12, h3, false);
  ov.setUint32(16, h4, false); ov.setUint32(20, h5, false);
  ov.setUint32(24, h6, false); ov.setUint32(28, h7, false);
  return out;
}

self.onmessage = function(e) {
  var prefix = e.data.p, difficulty = e.data.d, nonce = 0;
  var enc = new TextEncoder();
  while (true) {
    var candidate = prefix + nonce.toString(36);
    var hash = sha256(enc.encode(candidate));
    var fullBytes = difficulty >> 3, remainBits = difficulty & 7, ok = true;
    for (var i = 0; i < fullBytes; i++) { if (hash[i] !== 0) { ok = false; break; } }
    if (ok && remainBits > 0) {
      var mask = (0xff << (8 - remainBits)) & 0xff;
      if ((hash[fullBytes] & mask) !== 0) ok = false;
    }
    if (ok) { self.postMessage(nonce.toString(36)); return; }
    nonce++;
  }
};
