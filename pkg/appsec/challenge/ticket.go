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

// PoW difficulty levels in leading zero bits. Pure JS SHA-256 through the
// obfuscator runs ~500-5000 ops/sec, so keep these conservative.
const (
	PowDifficultyDisabled   = 0   // no PoW required, nonce "0" always valid
	PowDifficultyLow        = 10  // ~1024 avg iterations ≈ 0.2-2s
	PowDifficultyMedium     = 12  // ~4096 avg iterations ≈ 1-8s
	PowDifficultyHigh       = 15  // ~32768 avg iterations ≈ 7-60s
	PowDifficultyImpossible = 256 // full SHA-256 width: clients cannot solve, server always rejects

	defaultPowDifficulty = PowDifficultyMedium
)

// ticketAgeBackstop is a loose ceiling on accepted ticket age in
// matchesChallenge. The actual freshness gate is the keyring live
// window (rotationInterval × maxLiveEpochs); this is a separate ceiling
// that protects against operators configuring an unusually wide live
// window. Loose enough not to interfere with real submissions on slow
// clients (high-difficulty PoW) but tight enough to bound replay
// surface in pathological configurations.
const ticketAgeBackstop = 20 * time.Minute

// computeTicket signs the timestamp with the per-epoch signing key derived
// from the master secret. The epoch is computed from the timestamp itself
// (`ts_nanos / 1e9 / rotation_seconds`), so verification is fully stateless:
// any instance with the same master secret can derive the same epoch from the
// same ts and validate the HMAC.
func (c *ChallengeRuntime) computeTicket(ts string) string {
	epoch := c.epochForTimestamp(ts)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		// Falling back to the current key on out-of-window timestamps avoids
		// accidentally producing a structurally valid signature for a stale
		// timestamp; verification will reject the resulting ticket on the same
		// liveness check.
		_, signKey = c.keys.Current()
	}

	h := hmac.New(sha256.New, signKey)
	h.Write([]byte(ts))

	return fmt.Sprintf("%x", h.Sum(nil))
}

// epochForTimestamp converts a nanosecond UnixNano string (the format used in
// challenge.go's ts) into the keyring's epoch identifier. Uses the same
// rotation interval as the keyring so two instances always agree.
func (c *ChallengeRuntime) epochForTimestamp(ts string) int64 {
	tsVal, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || tsVal <= 0 {
		// Caller will reject the ticket via the liveness check anyway; return
		// an out-of-window sentinel epoch.
		return -1
	}
	return tsVal / int64(time.Second) / int64(c.keys.rotationInterval/time.Second)
}

// generatePowPrefix returns a freshly-generated 16-byte random PoW salt
// rendered as a hex string. Errors from crypto/rand.Read indicate a broken
// kernel entropy pool, which is recoverable at the request layer (we can
// reject the current challenge and let the client retry) — returning the
// error rather than panicking keeps a single failing request from taking
// down the whole WAF.
func generatePowPrefix() (string, error) {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		return "", fmt.Errorf("generate PoW prefix: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// computePowMAC produces an HMAC that authenticates a PoW salt as server-
// generated and bound to a specific ticket window. Signed with the same
// per-epoch key as the ticket so a single keyring lookup verifies both.
func (c *ChallengeRuntime) computePowMAC(salt, ticket, ts string) string {
	epoch := c.epochForTimestamp(ts)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		_, signKey = c.keys.Current()
	}

	h := hmac.New(sha256.New, signKey)
	h.Write([]byte(salt))
	h.Write([]byte(ticket))
	h.Write([]byte(ts))

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

func (c *ChallengeRuntime) getSessionKey(ticket string, nonce string) string {
	hash := sha256.Sum256([]byte(ticket + nonce))
	return fmt.Sprintf("%x", hash)
}

func (c *ChallengeRuntime) decryptFingerprint(sessionKey string, encrypted string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted fingerprint: %w", err)
	}

	decryptedBytes := make([]byte, len(encryptedBytes))

	for i := range encryptedBytes {
		decryptedBytes[i] = encryptedBytes[i] ^ sessionKey[i%len(sessionKey)]
	}

	return string(decryptedBytes), nil
}

// matchesChallenge verifies that the ticket/timestamp/PoW salt are authentically
// server-generated and the timestamp is recent. Fully stateless — any instance
// sharing the master secret can verify.
//
// Both the ticket and the PoW MAC are signed with the per-epoch key derived
// from `ts`. Liveness is enforced twice: first via the keyring (the epoch
// derived from `ts` must be in the live window) and second via the
// challenge-JS refresh window. The keyring window is the actual freshness
// guarantee; the JS-refresh check is a (looser) backstop.
func (c *ChallengeRuntime) matchesChallenge(clientTicket, clientTS, clientPowSalt, clientPowMAC string) bool {
	tsVal, err := strconv.ParseInt(clientTS, 10, 64)
	if err != nil || tsVal <= 0 {
		return false
	}

	age := time.Since(time.Unix(0, tsVal))
	if age < 0 || age > ticketAgeBackstop {
		return false
	}

	epoch := c.epochForTimestamp(clientTS)
	signKey, ok := c.keys.SignKey(epoch)
	if !ok {
		// Epoch fell out of the live window — reject without leaking a usable
		// "signature mismatch" vs "stale epoch" distinction via timing.
		return false
	}

	// Verify the ticket is an authentic HMAC of the timestamp under K_epoch.
	expectedTicket := hmacSHA256Hex(signKey, []byte(clientTS))
	if !hmac.Equal([]byte(clientTicket), []byte(expectedTicket)) {
		return false
	}

	// Verify the PoW salt MAC is authentic and bound to this ticket+timestamp.
	macIn := make([]byte, 0, len(clientPowSalt)+len(clientTicket)+len(clientTS))
	macIn = append(macIn, clientPowSalt...)
	macIn = append(macIn, clientTicket...)
	macIn = append(macIn, clientTS...)
	expectedMAC := hmacSHA256Hex(signKey, macIn)

	return hmac.Equal([]byte(clientPowMAC), []byte(expectedMAC))
}

func hmacSHA256Hex(key, msg []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return fmt.Sprintf("%x", h.Sum(nil))
}
