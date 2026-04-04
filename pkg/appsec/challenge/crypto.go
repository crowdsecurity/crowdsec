package challenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
)

const hkdfInfo = "crowdsec-challenge-cookie"

func deriveKey(secret string) ([]byte, error) {
	h := hkdf.New(sha256.New, []byte(secret), nil, []byte(hkdfInfo))
	key := make([]byte, 32) // AES-256

	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

func sealCookie(fpData *pb.FingerprintData, secret string, aad []byte) (string, error) {
	plaintext, err := proto.Marshal(fpData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal fingerprint proto: %w", err)
	}

	key, err := deriveKey(secret)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func openCookie(encoded string, secret string, aad []byte) (*pb.FingerprintData, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode: %w", ErrCookieMalformed, err)
	}

	key, err := deriveKey(secret)
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
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrCookieMalformed)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCookieSignature, err)
	}

	fpData := &pb.FingerprintData{}
	if err := proto.Unmarshal(plaintext, fpData); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCookiePayload, err)
	}

	return fpData, nil
}
