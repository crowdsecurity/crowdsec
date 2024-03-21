package exprhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLibinjectionHelpers(t *testing.T) {
	tests := []struct {
		name         string
		function     func(params ...any) (any, error)
		params       []any
		expectResult any
	}{
		{
			name:         "LibInjectionIsSQLI",
			function:     LibInjectionIsSQLI,
			params:       []any{"?__f__73=73&&__f__75=75&delivery=1&max=24.9&min=15.9&n=12&o=2&p=(select(0)from(select(sleep(15)))v)/*'%2B(select(0)from(select(sleep(15)))v)%2B'\x22%2B(select(0)from(select(sleep(15)))v)%2B\x22*/&rating=4"},
			expectResult: true,
		},
		{
			name:         "LibInjectionIsSQLI - no match",
			function:     LibInjectionIsSQLI,
			params:       []any{"?bla=42&foo=bar"},
			expectResult: false,
		},
		{
			name:         "LibInjectionIsSQLI - no match 2",
			function:     LibInjectionIsSQLI,
			params:       []any{"https://foo.com/asdkfj?bla=42&foo=bar"},
			expectResult: false,
		},
		{
			name:         "LibInjectionIsXSS",
			function:     LibInjectionIsXSS,
			params:       []any{"<script>alert('XSS')</script>"},
			expectResult: true,
		},
		{
			name:         "LibInjectionIsXSS - no match",
			function:     LibInjectionIsXSS,
			params:       []any{"?bla=42&foo=bar"},
			expectResult: false,
		},
		{
			name:         "LibInjectionIsXSS - no match 2",
			function:     LibInjectionIsXSS,
			params:       []any{"https://foo.com/asdkfj?bla=42&foo[]=bar&foo"},
			expectResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _ := test.function(test.params...)
			assert.Equal(t, test.expectResult, result)
		})
	}
}
