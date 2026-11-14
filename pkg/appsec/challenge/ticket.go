// ticket.go holds the per-challenge crypto handed to the browser and verified
// on submit: a random per-challenge nonce `r`, the PoW salt + its MAC, and the
// helpers to derive the per-challenge secret `s = HMAC(K_epoch, r)`. The browser
// solves the PoW (leading-zero-bits) and signs its submission with `s`;
// ValidateChallengeResponse (in challenge.go) re-derives `s`, checks the
// signature and PoW, then burns `r` (single-use). See the PowDifficulty*
// constants below for how the levels are calibrated.

package challenge

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// PoW difficulty levels in leading SHA-256 zero bits.
//
// A solution takes 2^d hashes in expectation (median 0.69*2^d, p99 4.6*2^d).
// The browser solves it in a pool of min(hardwareConcurrency, 4) Web Workers
// (see solvePoWAsync in challenge.js) running pow-worker.js, which is served
// unobfuscated precisely so it runs at full engine speed. Measured: 2.5M H/s
// on one worker and 10.2M H/s across four (Chromium 146, Ryzen 7 3700X).
//
// The levels are calibrated for the weakest device we still want to let
// through — a low-end 2-core phone, assumed at ~500k H/s aggregate — giving
// roughly 0.5s / 2s / 8s. A desktop is ~20x faster than that, so these are
// nearly free there; that spread is inherent to a fixed bit target.
const (
	PowDifficultyDisabled   = 0   // no PoW required, nonce "0" always valid
	PowDifficultyLow        = 18  // 2^18 = 262k hashes ≈ 0.5s low-end mobile, 0.03s desktop
	PowDifficultyMedium     = 20  // 2^20 = 1.05M hashes ≈ 2s low-end mobile, 0.10s desktop
	PowDifficultyHigh       = 22  // 2^22 = 4.19M hashes ≈ 8s low-end mobile, 0.41s desktop
	PowDifficultyImpossible = 256 // full SHA-256 width: clients cannot solve, server always rejects

	defaultPowDifficulty = PowDifficultyMedium
)

// ticketAgeBackstop is a loose ceiling on accepted submission age in
// verifyChallenge. The actual freshness gate is the keyring live
// window (rotationInterval × maxLiveEpochs); this is a separate ceiling
// that protects against operators configuring an unusually wide live
// window. Loose enough not to interfere with real submissions on slow
// clients (high-difficulty PoW) but tight enough to bound replay
// surface in pathological configurations.
const ticketAgeBackstop = 20 * time.Minute

// generateChallengeNonce returns a fresh 16-byte random per-challenge nonce
// (`r`) as hex. `r` keys single-use bookkeeping (spent_set.go) and seeds the
// per-challenge secret `s = HMAC(K_epoch, r)`. Error (not panic) on entropy
// failure so only the current request fails.
func generateChallengeNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		return "", fmt.Errorf("generate challenge nonce: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// deriveChallengeSecret computes the per-challenge signing secret
// `s = HMAC(K_epoch, r)` (hex). `s` is never transmitted; client and server
// derive it independently from the same per-epoch key.
func deriveChallengeSecret(signKey []byte, r string) string {
	return hmacSHA256Hex(signKey, []byte(r))
}

// epochForTimestamp converts a nanosecond UnixNano string (the format used in
// challenge.go's ts) into the keyring's epoch identifier. Uses the same
// rotation interval as the keyring so two instances always agree.
func (c *ChallengeRuntime) epochForTimestamp(ts string) int64 {
	tsVal, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || tsVal <= 0 {
		// Caller will reject the request via the liveness check anyway; return
		// an out-of-window sentinel epoch.
		return -1
	}
	return tsVal / int64(time.Second) / int64(c.keys.rotationInterval/time.Second)
}

// The browser's solver (pow-worker.js) hashes salt+nonce in a single SHA-256
// block, which is what makes it fast enough to justify the difficulty levels
// above. That budget is 55 bytes, and a base36 nonce can reach 11 chars, so the
// hex salt has to fit in the rest. The solver refuses to run on a salt that
// doesn't, this is the server's half of
// the contract. TestPowSaltFitsClientFastPath guards it.
const (
	powSaltBytes     = 16
	powSaltMaxHexLen = 44
)

// generatePowPrefix returns a freshly-generated random PoW salt rendered as a
// hex string. Errors from crypto/rand.Read indicate a broken kernel entropy
// pool, which is recoverable at the request layer (we can reject the current
// challenge and let the client retry) — returning the error rather than
// panicking keeps a single failing request from taking down the whole WAF.
func generatePowPrefix() (string, error) {
	buf := make([]byte, powSaltBytes)
	if _, err := crand.Read(buf); err != nil {
		return "", fmt.Errorf("generate PoW prefix: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// computePowMAC authenticates a PoW salt as server-generated and bound to a
// specific challenge (`r`) + timestamp + difficulty, signed with the per-epoch
// key.
func (c *ChallengeRuntime) computePowMAC(salt, r, ts string, difficulty int) string {
	epoch := c.epochForTimestamp(ts)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		_, signKey = c.keys.Current()
	}

	h := hmac.New(sha256.New, signKey)
	h.Write([]byte(salt))
	h.Write([]byte(r))
	h.Write([]byte(ts))
	h.Write([]byte(strconv.Itoa(difficulty)))

	return fmt.Sprintf("%x", h.Sum(nil))
}

func hasLeadingZeroBits(hash []byte, bits int) bool {
	fullBytes := bits / 8
	remainBits := bits % 8

	for i := range fullBytes {
		if hash[i] != 0 {
			return false
		}
	}

	if remainBits > 0 {
		mask := byte(0xFF << (8 - remainBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

// deriveFingerprintObfKey returns the keystream key for the fingerprint
// payload: `HMAC(s, "fpenc"||r)`.
func deriveFingerprintObfKey(s, r string) string {
	return hmacSHA256Hex([]byte(s), []byte("fpenc"+r))
}

// deobfuscateFingerprint reverses the client-side repeating-key XOR + base64
// applied to the fingerprint JSON, using the key from deriveFingerprintObfKey.
func deobfuscateFingerprint(obfKey string, payload string) (string, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("failed to decode obfuscated fingerprint: %w", err)
	}

	out := make([]byte, len(payloadBytes))

	for i := range payloadBytes {
		out[i] = payloadBytes[i] ^ obfKey[i%len(obfKey)]
	}

	return string(out), nil
}

// verifyChallenge gates timestamp freshness and authenticates the PoW-salt
// binding, returning the per-epoch sign key (for deriving `s`) on success.
// Stateless — any instance sharing the master secret can verify. Knowledge of
// the per-epoch key is proven separately by the caller's `sig` check.
func (c *ChallengeRuntime) verifyChallenge(clientR, clientTS, clientPowSalt, clientPowMAC string, clientDifficulty int) ([]byte, bool) {
	tsVal, err := strconv.ParseInt(clientTS, 10, 64)
	if err != nil || tsVal <= 0 {
		return nil, false
	}

	age := time.Since(time.Unix(0, tsVal))
	if age < 0 || age > ticketAgeBackstop {
		return nil, false
	}

	epoch := c.epochForTimestamp(clientTS)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		// Epoch fell out of the live window — reject without leaking a usable
		// "signature mismatch" vs "stale epoch" distinction via timing.
		return nil, false
	}

	// MAC is recomputed over the client-submitted difficulty: a tampered `d`
	// won't match, so this is what authenticates the difficulty.
	expectedMAC := c.computePowMAC(clientPowSalt, clientR, clientTS, clientDifficulty)

	if !hmac.Equal([]byte(clientPowMAC), []byte(expectedMAC)) {
		return nil, false
	}

	return signKey, true
}

func hmacSHA256Hex(key, msg []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return fmt.Sprintf("%x", h.Sum(nil))
}
