package journalctlacquisition

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellEscape(t *testing.T) {
    tests := []struct {
        in  string
        out string
    }{
        {"simple", "simple"},
        {"abc123", "abc123"},
        {"_", "_"},
        {"foo_bar", "foo_bar"},
        {"dot.value", "dot.value"},

        {"hello world", "'hello world'"},
        {"tabs\tare bad", "'tabs\tare bad'"},
        {"with-dash and space", "'with-dash and space'"},

        {`he said "hi"`, `'he said "hi"'`},

        {`he's here`, `'he'\''s here'`},
        {`a ' quoted`, `'a '\'' quoted'`},

        {`"'`, `'"'\'''`},

        {`back\slash`, `'back\slash'`},
        {`$HOME`, `'$HOME'`},
        {`*`, `'*'`},
        {`?`, `'?'`},
        {`a&b`, `'a&b'`},
        {"", ""},
    }

    for _, tt := range tests {
        t.Run(tt.in, func(t *testing.T) {
            assert.Equal(t, tt.out, shellEscape(tt.in))
        })
    }
}

func TestFormatShellCommand(t *testing.T) {
	tests := []struct {
		in  []string
		out string
	}{
		{
			[]string{"a", "b", "c"},
			"a b c",
		},
		{
			[]string{"echo", "hello world"},
			"echo 'hello world'",
		},
		{
			[]string{"foo", "bar baz", "qux"},
			"foo 'bar baz' qux",
		},
		{
			[]string{`he's`, "here"},
			`'he'\''s' here`,
		},
		// this would be wrong as it prevents variable expansion,
		// but we don't have them and don't expand anything in exec.Command anyway.
		{
			[]string{`$HOME`, `ls`, `-la`},
			"'$HOME' ls -la",
		},
		{
			[]string{},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {
			assert.Equal(t, tt.out, formatShellCommand(tt.in))
		})
	}
}
