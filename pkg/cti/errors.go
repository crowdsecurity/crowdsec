package cti

import (
	"errors"
)

var (
	ErrDisabled = errors.New("CTI is disabled")
	ErrLimit   = errors.New("request quota exceeeded, please reduce your request rate")
	ErrUnauthorized = errors.New("unauthorized")
	ErrUnknown = errors.New("unknown error")
)
