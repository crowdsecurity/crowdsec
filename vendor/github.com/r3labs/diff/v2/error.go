package diff

import (
	"fmt"
)

var (
	// ErrTypeMismatch Compared types do not match
	ErrTypeMismatch = NewError("types do not match")
	// ErrInvalidChangeType The specified change values are not unsupported
	ErrInvalidChangeType = NewError("change type must be one of 'create' or 'delete'")
)

//our own version of an error, which can wrap others
type DiffError struct {
	count   int
	message string
	next    error
}

//Unwrap implement 1.13 unwrap feature for compatibility
func (s *DiffError) Unwrap() error {
	return s.next
}

//Error implements the error interface
func (s DiffError) Error() string {
	cause := ""
	if s.next != nil {
		cause = s.next.Error()
	}
	return fmt.Sprintf(" %s (cause count %d)\n%s", s.message, s.count, cause)
}

//AppendCause appends a new cause error to the chain
func (s *DiffError) WithCause(err error) *DiffError {
	if s != nil && err != nil {
		s.count++
		if s.next != nil {
			if v, ok := err.(DiffError); ok {
				s.next = v.WithCause(s.next)
			} else if v, ok := err.(*DiffError); ok {
				s.next = v.WithCause(s.next)
			} else {
				v = &DiffError{
					message: "auto wrapped error",
					next:    err,
				}
				s.next = v.WithCause(s.next)
			}
		} else {
			s.next = err
		}
	}
	return s
}

//NewErrorf just give me a plain error with formatting
func NewErrorf(format string, messages ...interface{}) *DiffError {
	return &DiffError{
		message: fmt.Sprintf(format, messages...),
	}
}

//NewError just give me a plain error
func NewError(message string, causes ...error) *DiffError {
	s := &DiffError{
		message: message,
	}
	for _, cause := range causes {
		s.WithCause(cause) // nolint: errcheck
	}
	return s
}
