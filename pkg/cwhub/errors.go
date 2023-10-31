package cwhub

import (
	"errors"
)

var (
	// ErrNilRemoteHub is returned when the remote hub configuration is not provided to the NewHub constructor.
	// All attempts to download index or items will return this error.
	ErrMissingReference = errors.New("Reference(s) missing in collection")
	ErrNilRemoteHub = errors.New("remote hub configuration is not provided. Please report this issue to the developers")
)
