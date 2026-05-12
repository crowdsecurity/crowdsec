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
	ErrCookieMalformed = errors.New("malformed cookie")
	ErrCookieSignature = errors.New("invalid cookie signature")
	ErrCookiePayload   = errors.New("invalid cookie payload")
	ErrCookieExpired   = errors.New("cookie expired")
	ErrCookieVersion   = errors.New("unknown cookie version")
)

const hkdfInfo = "crowdsec-challenge-cookie"

// Cookie wire format. A single version byte at offset 0 lets us evolve the
// format without flag-day-style cookie invalidation. New formats add a new
// case in openCookie's switch.
//
//	v0: cookieVersionV0 || nonce(12) || ciphertext
//
//	    Sealed under KeyRing.MasterCookieKey() — a long-lived AES-GCM key
//	    derived from master_secret with no epoch dependency. Cookie
//	    expiration is enforced by an explicit unix-seconds not_after
//	    timestamp prepended to the plaintext BEFORE encryption, so any
//	    tampering with the expiration invalidates the AEAD tag. AAD is
//	    the User-Agent.
//
//	    Decoupling the cookie key from the epoch keyring is what lets us
//	    have e.g. 24h cookies while keeping ticket-signing keys rotating
//	    every few minutes — the two security windows are independent.
const cookieVersionV0 byte = 0x00

// cookiePlaintextHeaderLen is the size of the not_after_be8 prefix that
// gets glued in front of the marshalled ChallengeCookie proto before
// AES-GCM seal. It is INSIDE the encrypted+authenticated envelope.
const cookiePlaintextHeaderLen = 8

func deriveKey(secret []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, secret, nil, []byte(hkdfInfo))
	key := make([]byte, 32) // AES-256

	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// sealCookieV0 produces a v0 cookie sealed under the long-lived master
// cookie key. notAfter is the unix-seconds expiration; it is prepended to
// the marshalled proto BEFORE encryption so it is both confidential (not
// observable from the wire) and authenticated (any tamper attempt
// invalidates the GCM tag).
func sealCookieV0(envelope *pb.ChallengeCookie, masterCookieKey []byte, notAfter int64, aad []byte) (string, error) {
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

	// Build the plaintext: not_after_be8 || envelope_bytes
	plaintext := make([]byte, 0, cookiePlaintextHeaderLen+len(envelopeBytes))
	var notAfterBytes [cookiePlaintextHeaderLen]byte
	binary.BigEndian.PutUint64(notAfterBytes[:], uint64(notAfter))
	plaintext = append(plaintext, notAfterBytes[:]...)
	plaintext = append(plaintext, envelopeBytes...)

	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)

	// Wire form: version || nonce || ciphertext
	out := make([]byte, 0, 1+len(ciphertext))
	out = append(out, cookieVersionV0)
	out = append(out, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// openCookie decodes a sealed cookie, dispatching on the version byte.
// Unknown versions are rejected with ErrCookieVersion. Expired cookies
// (notAfter <= now) are rejected with ErrCookieExpired.
func openCookie(encoded string, masterCookieKey []byte, aad []byte) (*pb.ChallengeCookie, error) {
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

func openCookieV0Bytes(body []byte, masterCookieKey []byte, aad []byte, now time.Time) (*pb.ChallengeCookie, error) {
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

	if len(plaintext) < cookiePlaintextHeaderLen {
		return nil, fmt.Errorf("%w: plaintext shorter than not_after header", ErrCookieMalformed)
	}

	notAfter := int64(binary.BigEndian.Uint64(plaintext[:cookiePlaintextHeaderLen]))
	if notAfter <= now.Unix() {
		return nil, fmt.Errorf("%w: not_after=%d now=%d", ErrCookieExpired, notAfter, now.Unix())
	}

	envelope := &pb.ChallengeCookie{}
	if err := proto.Unmarshal(plaintext[cookiePlaintextHeaderLen:], envelope); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCookiePayload, err)
	}

	return envelope, nil
}
