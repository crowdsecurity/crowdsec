package cwhub

import (
	"errors"
	"fmt"
)

var (
	// ErrNilRemoteHub is returned when the remote hub configuration is not provided to the NewHub constructor.
	ErrNilRemoteHub = errors.New("remote hub configuration is not provided. Please report this issue to the developers")
)

// IndexNotFoundError is returned when the remote hub index is not found.
type IndexNotFoundError struct {
	URL    string
	Branch string
}

func (e IndexNotFoundError) Error() string {
	return fmt.Sprintf("index not found at %s, branch '%s'. Please check the .cscli.hub_branch value if you specified it in config.yaml, or use 'master' if not sure", e.URL, e.Branch)
}
