package internal

import (
	"errors"
	"fmt"
)

// NoResponderFound is returned when no responders are found for a
// given HTTP method and URL.
var NoResponderFound = errors.New("no responder found") // nolint: revive

// errorNoResponderFoundMethodCase encapsulates a NoResponderFound
// error probably due to the method not upper-cased.
type ErrorNoResponderFoundWrongMethod struct {
	orig      string // original wrong method, without any matching responder
	suggested string // suggested method with a matching responder
}

// NewErrorNoResponderFoundWrongMethod returns an ErrorNoResponderFoundWrongMethod.
func NewErrorNoResponderFoundWrongMethod(orig, suggested string) error {
	return &ErrorNoResponderFoundWrongMethod{
		orig:      orig,
		suggested: suggested,
	}
}

// Unwrap implements the interface needed by errors.Unwrap.
func (e *ErrorNoResponderFoundWrongMethod) Unwrap() error {
	return NoResponderFound
}

// Error implements error interface.
func (e *ErrorNoResponderFoundWrongMethod) Error() string {
	return fmt.Sprintf("%s for method %s, but one matches method %s",
		NoResponderFound,
		e.orig,
		e.suggested,
	)
}
