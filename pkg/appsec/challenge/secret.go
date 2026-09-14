// secret.go parses and validates the master-secret used by the keyring, and
// generates a random fallback when none is configured. The secret is the
// trust anchor for every per-epoch HMAC key and the cookie-sealing AES key,
// so any change here is wire-protocol-affecting.

package challenge

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// minSecretBytes is the smallest accepted master-secret length. 32 bytes is
// the natural minimum for an HMAC-SHA256 key with full security margin; we
// reject anything shorter as a configuration error rather than silently
// padding it.
const minSecretBytes = 32

// generateRandomSecret returns a fresh 32-byte secret suitable for use when
// no master_secret is configured. Single-instance deployments are fine with
// this; distributed deployments MUST configure a shared secret because each
// instance generates an independent random one here.
func generateRandomSecret() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := crand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate random master secret: %w", err)
	}
	return buf, nil
}

// ParseConfiguredSecret accepts a configured master secret as either a hex
// string (preferred — encodes raw bytes unambiguously) or a raw passphrase
// (fallback for human-edited configs). The result is at least minSecretBytes.
func ParseConfiguredSecret(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty master secret")
	}

	// Hex form: even length, hex digits only.
	if isHex(value) {
		raw, err := hex.DecodeString(value)
		if err == nil {
			if len(raw) < minSecretBytes {
				return nil, fmt.Errorf("hex master secret decodes to %d bytes; minimum is %d", len(raw), minSecretBytes)
			}
			return raw, nil
		}
		// Fall through to passphrase handling on hex parse failure — defensive.
	}

	if len(value) < minSecretBytes {
		return nil, fmt.Errorf("passphrase master secret is %d bytes; minimum is %d", len(value), minSecretBytes)
	}

	return []byte(value), nil
}

func isHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
