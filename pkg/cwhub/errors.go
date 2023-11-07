package cwhub

import (
	"errors"
)

var (
	// ErrNilRemoteHub is returned when the remote hub configuration is not provided to the NewHub constructor.
	// All attempts to download index or items will return this error.
	ErrNilRemoteHub = errors.New("remote hub configuration is not provided. Please report this issue to the developers")
	ErrIndexNotFound = errors.New("index not found")
)
