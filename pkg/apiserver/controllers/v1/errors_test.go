package v1

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollapseRepeatedPrefix(t *testing.T) {
	tests := []struct {
		input  string
		prefix string
		want   string
	}{
		{
			input:  "aaabbbcccaaa",
			prefix: "aaa",
			want:   "aaabbbcccaaa",
		}, {
			input:  "hellohellohello world",
			prefix: "hello",
			want:   "hello world",
		}, {
			input:  "ababababxyz",
			prefix: "ab",
			want:   "abxyz",
		}, {
			input:  "xyzxyzxyzxyzxyz",
			prefix: "xyz",
			want:   "xyz",
		}, {
			input:  "123123123456",
			prefix: "456",
			want:   "123123123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, collapseRepeatedPrefix(tt.input, tt.prefix))
		})
	}
}

func TestRepeatedPrefixError(t *testing.T) {
	originalErr := errors.New("hellohellohello world")
	wrappedErr := RepeatedPrefixError{OriginalError: originalErr, Prefix: "hello"}

	want := "hello world"

	assert.Equal(t, want, wrappedErr.Error())

	assert.Equal(t, originalErr, errors.Unwrap(wrappedErr))
	require.ErrorIs(t, wrappedErr, originalErr)
}
