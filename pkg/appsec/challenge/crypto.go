// crypto.go implements AES-GCM cookie sealing/unsealing for the challenge
// cookie envelope: a versioned, integrity-protected blob carrying the
// fingerprint proto bytes plus a not_after expiration timestamp. The
// encryption key comes from the keyring (cookie-master derivation, long
// lifetime); rotation is handled by the keyring, not by this file. All
// helpers here are pure functions over byte slices — no IO, no globals.

package challenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
	"google.golang.org/protobuf/proto"
)

var (
	ErrCookieMalformed     = errors.New("malformed cookie")
	ErrCookieSignature     = errors.New("invalid cookie signature")
	ErrCookiePayload       = errors.New("invalid cookie payload")
	ErrCookieExpired       = errors.New("cookie expired")
	ErrCookieVersion       = errors.New("unknown cookie version")
	ErrAllowlistReasonSize = errors.New("allowlist reason exceeds maximum length")
)

const hkdfInfo = "crowdsec-challenge-cookie"

// MaxAllowlistReasonLen caps the reason string operators pass to
// GrantChallengeCookie. The reason travels inside every Set-Cookie + Cookie
// header round-trip until the cookie expires; bounding it keeps the cookie
// well under the 4 KB browser limit even with the AES-GCM tag + base64
// expansion.
const MaxAllowlistReasonLen = 256

// Cookie wire format. A single version byte at offset 0 lets us evolve the
// format without flag-day-style cookie invalidation. New formats add a new
// case in openCookie's switch.
//
//	v0: cookieVersionV0 || nonce(12) || ciphertext
//
//	    Sealed under KeyRing.MasterCookieKey() — a long-lived AES-GCM key
//	    derived from master_secret with no epoch dependency. AAD is the
//	    User-Agent.
//
//	    Plaintext layout (inside the AEAD envelope):
//
//	      not_after_be8       (8 bytes BE, unix seconds)
//	      flags_byte          (1 byte; bit 0 = allowlisted, bits 1-7 reserved)
//	      reason_len_be       (2 bytes BE, length of reason_bytes)
//	      reason_bytes        (0..MaxAllowlistReasonLen UTF-8 bytes)
//	      protobuf(envelope)
//
//	    All four header fields are inside the AEAD envelope, so any
//	    tampering with them invalidates the GCM tag.
//
//	    Decoupling the cookie key from the epoch keyring is what lets us
//	    have e.g. 12h cookies while keeping ticket-signing keys rotating
//	    every few minutes — the two security windows are independent.
const cookieVersionV0 byte = 0x00

// cookiePlaintextFixedHeaderLen is the size of the fixed-layout portion of
// the plaintext header that precedes the protobuf envelope:
//
//	not_after_be8 (8) + flags_byte (1) + reason_len_be (2) = 11
//
// followed by reason_bytes (variable, 0..MaxAllowlistReasonLen).
const cookiePlaintextFixedHeaderLen = 8 + 1 + 2

// cookieFlagAllowlisted marks a cookie minted by GrantChallengeCookie
// (operator allowlist bypass) rather than by a real challenge submission.
const cookieFlagAllowlisted byte = 0x01

func deriveKey(secret []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, secret, nil, []byte(hkdfInfo))
	key := make([]byte, 32) // AES-256

	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// sealCookieV0 produces a v0 cookie sealed under the long-lived master
// cookie key. notAfter is the unix-seconds expiration; flags carries the
// allowlist bit set by GrantChallengeCookie (0 for normal cookies);
// reason is the operator-supplied allowlist reason (empty for normal
// cookies). All three are prepended to the marshalled proto BEFORE
// encryption so they are both confidential (not observable from the wire)
// and authenticated (any tamper attempt invalidates the GCM tag).
//
// Returns ErrAllowlistReasonSize if reason exceeds MaxAllowlistReasonLen.
func sealCookieV0(envelope *pb.ChallengeCookie, masterCookieKey []byte, notAfter int64, flags byte, reason string, aad []byte) (string, error) {
	if len(reason) > MaxAllowlistReasonLen {
		return "", fmt.Errorf("%w: %d > %d", ErrAllowlistReasonSize, len(reason), MaxAllowlistReasonLen)
	}

	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("failed to marshal challenge cookie proto: %w", err)
	}

	key, err := deriveKey(masterCookieKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build the plaintext: not_after_be8 || flags || reason_len_be || reason || envelope
	plaintext := make([]byte, 0, cookiePlaintextFixedHeaderLen+len(reason)+len(envelopeBytes))

	var notAfterBytes [8]byte
	binary.BigEndian.PutUint64(notAfterBytes[:], uint64(notAfter))
	plaintext = append(plaintext, notAfterBytes[:]...)

	plaintext = append(plaintext, flags)

	var reasonLenBytes [2]byte
	binary.BigEndian.PutUint16(reasonLenBytes[:], uint16(len(reason)))
	plaintext = append(plaintext, reasonLenBytes[:]...)

	plaintext = append(plaintext, []byte(reason)...)
	plaintext = append(plaintext, envelopeBytes...)

	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)

	// Wire form: version || nonce || ciphertext
	out := make([]byte, 0, 1+len(ciphertext))
	out = append(out, cookieVersionV0)
	out = append(out, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// CookieEnvelope bundles the proto payload with the header fields that
// openCookie pulls out of the AEAD-sealed plaintext: allowlist marker,
// allowlist reason, expiration. Returned by openCookie so callers can
// route allowlist cookies differently from real-submission ones without
// re-parsing the plaintext.
type CookieEnvelope struct {
	Envelope        *pb.ChallengeCookie
	Allowlisted     bool
	AllowlistReason string
	NotAfter        int64
}

// openCookie decodes a sealed cookie, dispatching on the version byte.
// Unknown versions are rejected with ErrCookieVersion. Expired cookies
// (notAfter <= now) are rejected with ErrCookieExpired.
func openCookie(encoded string, masterCookieKey []byte, aad []byte) (*CookieEnvelope, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode: %w", ErrCookieMalformed, err)
	}
	if len(raw) < 1 {
		return nil, fmt.Errorf("%w: empty cookie", ErrCookieMalformed)
	}

	switch raw[0] {
	case cookieVersionV0:
		return openCookieV0Bytes(raw[1:], masterCookieKey, aad, time.Now())
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrCookieVersion, raw[0])
	}
}

func openCookieV0Bytes(body []byte, masterCookieKey []byte, aad []byte, now time.Time) (*CookieEnvelope, error) {
	key, err := deriveKey(masterCookieKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(body) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrCookieMalformed)
	}

	nonce, ciphertext := body[:nonceSize], body[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCookieSignature, err)
	}

	if len(plaintext) < cookiePlaintextFixedHeaderLen {
		return nil, fmt.Errorf("%w: plaintext shorter than fixed header", ErrCookieMalformed)
	}

	notAfter := int64(binary.BigEndian.Uint64(plaintext[:8]))
	flags := plaintext[8]
	reasonLen := int(binary.BigEndian.Uint16(plaintext[9:11]))

	if reasonLen > MaxAllowlistReasonLen {
		return nil, fmt.Errorf("%w: reason_len=%d", ErrCookieMalformed, reasonLen)
	}

	if len(plaintext) < cookiePlaintextFixedHeaderLen+reasonLen {
		return nil, fmt.Errorf("%w: plaintext shorter than declared reason_len", ErrCookieMalformed)
	}

	if notAfter <= now.Unix() {
		return nil, fmt.Errorf("%w: not_after=%d now=%d", ErrCookieExpired, notAfter, now.Unix())
	}

	reasonStart := cookiePlaintextFixedHeaderLen
	reasonEnd := reasonStart + reasonLen
	reason := string(plaintext[reasonStart:reasonEnd])

	envelope := &pb.ChallengeCookie{}
	if err := proto.Unmarshal(plaintext[reasonEnd:], envelope); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCookiePayload, err)
	}

	return &CookieEnvelope{
		Envelope:        envelope,
		Allowlisted:     flags&cookieFlagAllowlisted != 0,
		AllowlistReason: reason,
		NotAfter:        notAfter,
	}, nil
}
