// PoW solver worker. Served unobfuscated (see PowWorkerJS in challenge.go)
//
// The page spawns one of these per core (capped) and gives each a disjoint
// slice of the nonce space: worker i searches start=i, stride=n, so together
// they cover every nonce exactly once.
//
// The salt is always 32 hex chars (generatePowPrefix in ticket.go), so a
// candidate always fits one 64-byte SHA-256 block.
//
// in : { p: salt, d: bits, start: int, stride: int }
// out: base36 nonce string
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

// A message under 56 bytes pads into a single 64-byte block (64 minus the 0x80
// terminator and the 8-byte length field).
var SINGLE_BLOCK_MAX = 55;
// Number.MAX_SAFE_INTEGER in base36 is 11 chars, so the nonce can never outgrow
// this no matter how long the search runs.
var MAX_NONCE_CHARS = 11;
// Keep in sync with powSaltMaxHexLen in ticket.go.
var MAX_SALT_BYTES = SINGLE_BLOCK_MAX - MAX_NONCE_CHARS;

// Scratch reused across every iteration: the whole point is that the inner loop
// allocates nothing.
var msg = new Uint8Array(64);
var dv = new DataView(msg.buffer);
var w = new Int32Array(64);
var digits = new Uint8Array(MAX_NONCE_CHARS);
var H1 = 0; // second output word, only read when difficulty > 32

// compress runs one SHA-256 block over msg and returns h0 (h1 lands in H1).
// The salt never changes between iterations, so when it covers a whole number
// of 32-bit words we reload only the tail of the schedule.
function compress(fixedWords) {
  for (var i = fixedWords; i < 16; i++) w[i] = dv.getInt32(i << 2, false);
  for (var i = 16; i < 64; i++) {
    var x = w[i - 15], y = w[i - 2];
    var s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) | 0;
    var s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) | 0;
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  var a = 0x6a09e667 | 0, b = 0xbb67ae85 | 0, c = 0x3c6ef372 | 0, d = 0xa54ff53a | 0,
      e = 0x510e527f | 0, f = 0x9b05688c | 0, g = 0x1f83d9ab | 0, h = 0x5be0cd19 | 0;
  for (var i = 0; i < 64; i++) {
    var S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) | 0;
    var t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
    var S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) | 0;
    var t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  H1 = ((0xbb67ae85 | 0) + b) | 0;
  return ((0x6a09e667 | 0) + a) | 0;
}

// writeNonce renders n as lowercase base36 into msg at off and returns its
// length. Digits come out least-significant first, so they are reversed on the
// way into the buffer.
function writeNonce(n, off) {
  if (n === 0) { msg[off] = 48; return 1; }
  var len = 0;
  while (n > 0) {
    var r = n % 36;
    digits[len++] = r < 10 ? 48 + r : 87 + r;
    n = (n - r) / 36;
  }
  for (var i = 0; i < len; i++) msg[off + i] = digits[len - 1 - i];
  return len;
}

// saltBytes returns the salt as ASCII bytes, or null if it isn't plain ASCII or
// is too long to leave room for a nonce inside one block.
function saltBytes(s) {
  if (s.length > MAX_SALT_BYTES) return null;
  var out = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c > 127) return null;
    out[i] = c;
  }
  return out;
}

function solve(salt, difficulty, start, stride) {
  var p = salt.length;
  msg.fill(0);
  msg.set(salt, 0);

  var fixedWords = (p & 3) === 0 ? p >> 2 : 0;
  // compress() only refills w[fixedWords..15], so load the invariant salt
  // words once up front.
  for (var i = 0; i < fixedWords; i++) w[i] = dv.getInt32(i << 2, false);

  // Test the output words directly against a shifted mask instead of building
  // and scanning a 32-byte digest.
  var wide = difficulty > 32;
  var shift0 = wide ? 0 : 32 - difficulty;
  var shift1 = wide ? 64 - difficulty : 0;

  // The nonce climbs, so its base36 length never shrinks: a longer one
  // overwrites the previous terminator itself, and everything past it is still
  // zero from the fill above. Nothing needs clearing between iterations.
  for (var nonce = start; ; nonce += stride) {
    var len = writeNonce(nonce, p);
    msg[p + len] = 0x80;
    // p + len <= 55 keeps the bit length inside w[15], so w[14] stays zero.
    dv.setUint32(60, (p + len) << 3, false);

    var h0 = compress(fixedWords);
    if (wide ? (h0 === 0 && (H1 >>> shift1) === 0) : ((h0 >>> shift0) === 0)) {
      return nonce.toString(36);
    }
  }
}

self.onmessage = function (e) {
  var m = e.data || {};
  var difficulty = m.d | 0;

  // d <= 0 is "disabled". d > 64 is the server's Impossible hard-block, which
  // is rejected before the nonce is ever looked at — searching for it would
  // just pin every core forever.
  if (difficulty <= 0 || difficulty > 64) {
    self.postMessage("0");
    return;
  }

  var salt = saltBytes(String(m.p == null ? "" : m.p));
  if (salt === null) {
    // Fail loudly: a salt this shape means the server broke its own contract,
    // and solving anything at this point would only produce a nonce it rejects.
    throw new Error("pow: unusable salt");
  }

  self.postMessage(solve(salt, difficulty, m.start | 0, (m.stride | 0) || 1));
};
