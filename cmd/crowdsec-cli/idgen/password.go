package idgen

import (
	saferand "crypto/rand"
	"math/big"

	log "github.com/sirupsen/logrus"
)

const PasswordLength = 64

func GeneratePassword(length int) string {
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXY"
	lower := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"

	charset := upper + lower + digits
	charsetLength := len(charset)

	buf := make([]byte, length)

	for i := range length {
		rInt, err := saferand.Int(saferand.Reader, big.NewInt(int64(charsetLength)))
		if err != nil {
			log.Fatalf("failed getting data from prng for password generation : %s", err)
		}

		buf[i] = charset[rInt.Int64()]
	}

	return string(buf)
}
