package main

import (
	"math/rand"
	"time"
)

var (
	passwordLength = 64
	upper          = "ABCDEFGHIJKLMNOPQRSTUVWXY"
	lower          = "abcdefghijklmnopqrstuvwxyz"
	digits         = "0123456789"
)

var (
	userID string // for flag parsing

)

const (
	uuid          = "/proc/sys/kernel/random/uuid"
	apiConfigFile = "api.yaml"
)

func generatePassword() string {
	rand.Seed(time.Now().UnixNano())
	charset := upper + lower + digits

	buf := make([]byte, passwordLength)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = upper[rand.Intn(len(upper))]
	buf[2] = lower[rand.Intn(len(lower))]

	for i := 3; i < passwordLength; i++ {
		buf[i] = charset[rand.Intn(len(charset))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})

	return string(buf)
}
