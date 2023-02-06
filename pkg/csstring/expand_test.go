package csstring_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/csstring"
)

func TestStrictExpand(t *testing.T) {
	t.Parallel()

	testenv := func(key string) (string, bool) {
		switch key {
		case "USER":
			return "testuser", true
		case "HOME":
			return "/home/testuser", true
		case "empty":
			return "", true
		default:
			return "", false
		}
	}

	home, _ := testenv("HOME")
	user, _ := testenv("USER")

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "$HOME",
			expected: home,
		},
		{
			input:    "${USER}",
			expected: user,
		},
		{
			input:    "Hello, $USER!",
			expected: fmt.Sprintf("Hello, %s!", user),
		},
		{
			input:    "My home directory is ${HOME}",
			expected: fmt.Sprintf("My home directory is %s", home),
		},
		{
			input:    "This is a $SINGLE_VAR string with ${HOME}",
			expected: fmt.Sprintf("This is a $SINGLE_VAR string with %s", home),
		},
		{
			input:    "This is a $SINGLE_VAR string with $HOME",
			expected: fmt.Sprintf("This is a $SINGLE_VAR string with %s", home),
		},
		{
			input:    "This variable does not exist: $NON_EXISTENT_VAR",
			expected: "This variable does not exist: $NON_EXISTENT_VAR",
		},
		{
			input:    "This is a $MULTI_VAR string with ${HOME} and ${USER}",
			expected: fmt.Sprintf("This is a $MULTI_VAR string with %s and %s", home, user),
		},
		{
			input:    "This is a ${MULTI_VAR} string with $HOME and $USER",
			expected: fmt.Sprintf("This is a ${MULTI_VAR} string with %s and %s", home, user),
		},
		{
			input:    "This is a plain string with no variables",
			expected: "This is a plain string with no variables",
		},
		{
			input:    "$empty",
			expected: "",
		},
		{
			input:    "",
			expected: "",
		},
		{
			input:    "$USER:$empty:$HOME",
			expected: fmt.Sprintf("%s::%s", user, home),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			output := csstring.StrictExpand(tc.input, testenv)
			assert.Equal(t, tc.expected, output)
		})
	}
}
