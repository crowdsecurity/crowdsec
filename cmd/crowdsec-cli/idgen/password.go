package idgen

import (
	saferand "crypto/rand"
	"fmt"
	"math/big"
)

const PasswordLength = 64

func GeneratePassword(length int) (string, error) {
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXY"
	lower := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"

	charset := upper + lower + digits
	charsetLength := len(charset)

	buf := make([]byte, length)

	for i := range length {
		rInt, err := saferand.Int(saferand.Reader, big.NewInt(int64(charsetLength)))
		if err != nil {
			return "", fmt.Errorf("prng failed to generate unique id or password: %w", err)
		}

		buf[i] = charset[rInt.Int64()]
	}

	return string(buf), nil
}
