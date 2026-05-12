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

	"golang.org/x/crypto/hkdf"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
	"google.golang.org/protobuf/proto"
)

var (
	ErrCookieMalformed = errors.New("malformed cookie")
	ErrCookieSignature = errors.New("invalid cookie signature")
	ErrCookiePayload   = errors.New("invalid cookie payload")
	ErrCookieEpoch     = errors.New("cookie epoch outside live window")
	ErrCookieVersion   = errors.New("unknown cookie version")
)

const hkdfInfo = "crowdsec-challenge-cookie"

// Cookie wire format. A single version byte at offset 0 lets us evolve the
// format without flag-day-style cookie invalidation. New formats add a new
// case in openCookie's switch.
//
//   v1: cookieVersionV1 || epoch_be8 || nonce || ciphertext
//
// The epoch is bound into the AAD so a sealed cookie can't be replayed
// under a different epoch tag.
const cookieVersionV1 byte = 0x01

func deriveKey(secret []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, secret, nil, []byte(hkdfInfo))
	key := make([]byte, 32) // AES-256

	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// sealCookieV1 produces a v1 cookie sealed under the given per-epoch key.
// The epoch is included in both the wire format header and the AEAD AAD so
// a cookie sealed for epoch N cannot be replayed claiming epoch M.
func sealCookieV1(envelope *pb.ChallengeCookie, epochKey []byte, epoch int64, aad []byte) (string, error) {
	plaintext, err := proto.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("failed to marshal challenge cookie proto: %w", err)
	}

	key, err := deriveKey(epochKey)
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

	// Bind the epoch into the AAD: changing the epoch tag invalidates the AEAD tag.
	bound := bindEpochToAAD(aad, epoch)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, bound)

	// Build the v1 wire form: version || epoch_be8 || (nonce || ciphertext).
	out := make([]byte, 0, 1+8+len(ciphertext))
	out = append(out, cookieVersionV1)
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], uint64(epoch))
	out = append(out, epochBytes[:]...)
	out = append(out, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// keyResolver returns the per-epoch cookie key for a given epoch, or
// (nil, false) if the epoch is outside the live window. Implemented by
// KeyRing.CookieKey.
type keyResolver func(epoch int64) ([]byte, bool)

// openCookie decodes a sealed cookie, dispatching on the version byte.
// Unknown versions are rejected with ErrCookieVersion — there is no legacy
// fallback because the cookie format has never shipped to users in any
// earlier form.
func openCookie(encoded string, resolveKey keyResolver, aad []byte) (*pb.ChallengeCookie, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode: %w", ErrCookieMalformed, err)
	}
	if len(raw) < 1 {
		return nil, fmt.Errorf("%w: empty cookie", ErrCookieMalformed)
	}

	switch raw[0] {
	case cookieVersionV1:
		return openCookieV1Bytes(raw, resolveKey, aad)
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrCookieVersion, raw[0])
	}
}

func openCookieV1Bytes(raw []byte, resolveKey keyResolver, aad []byte) (*pb.ChallengeCookie, error) {
	const headerLen = 1 + 8 // version + epoch
	if len(raw) < headerLen {
		return nil, fmt.Errorf("%w: v1 header too short", ErrCookieMalformed)
	}

	epoch := int64(binary.BigEndian.Uint64(raw[1:headerLen]))
	body := raw[headerLen:]

	key, ok := resolveKey(epoch)
	if !ok {
		return nil, fmt.Errorf("%w: epoch %d", ErrCookieEpoch, epoch)
	}

	return openCookieAESGCM(body, key, bindEpochToAAD(aad, epoch))
}

func openCookieAESGCM(body []byte, epochKey []byte, aad []byte) (*pb.ChallengeCookie, error) {
	key, err := deriveKey(epochKey)
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

	envelope := &pb.ChallengeCookie{}
	if err := proto.Unmarshal(plaintext, envelope); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCookiePayload, err)
	}

	return envelope, nil
}

// bindEpochToAAD returns the AEAD AAD with a length-prefixed epoch suffix so
// the underlying AAD bytes (User-Agent) can have any length without the
// epoch's bytes ambiguously merging with them.
func bindEpochToAAD(aad []byte, epoch int64) []byte {
	out := make([]byte, 0, len(aad)+1+8)
	out = append(out, aad...)
	out = append(out, '|')
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], uint64(epoch))
	return append(out, epochBytes[:]...)
}
