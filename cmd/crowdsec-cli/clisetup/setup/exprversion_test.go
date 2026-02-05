package setup

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestVersionCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version    string
		constraint string
		want       bool
		wantErr    string
	}{
		{"1", "=1", true, ""},
		{"1", "!=1", false, ""},
		{"1", "<=1", true, ""},
		{"1", ">1", false, ""},
		{"1", ">=1", true, ""},
		{"1.0", "<1.0", false, ""},
		{"1", "<1", false, ""},
		{"1.3.5", "1.3", true, ""},
		{"1.0", "<1.0", false, ""},
		{"1.0", "<=1.0", true, ""},
		{"2", ">1, <3", true, ""},
		{"2", "<=2, >=2.2", false, ""},
		{"2.3", "~2", true, ""},
		{"2.3", "=2", true, ""},
		{"1.1.1", "=1.1", true, ""},
		{"1.1.1", "1.1", true, ""},
		{"1.1", "!=1.1.1", true, ""},
		{"1.1", "~1.1.1", false, ""},
		{"1.1.1", "~1.1", true, ""},
		{"1.1.3", "~1.1", true, ""},
		{"19.04", "<19.10", true, ""},
		{"19.04", ">=19.10", false, ""},
		{"19.04", "=19.4", true, ""},
		{"19.04", "~19.4", true, ""},
		{"1.2.3", "~1.2", true, ""},
		{"1.2.3", "!=1.2", false, ""},
		{"1.2.3", "1.1.1 - 1.3.4", true, ""},
		{"1.3.5", "1.1.1 - 1.3.4", false, ""},
		{"1.3.5", "=1", true, ""},
		{"1.3.5", "1", true, ""},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Check(%s,%s)", tc.version, tc.constraint), func(t *testing.T) {
			t.Parallel()

			v := &ExprVersion{}
			actual, err := v.Check(tc.version, tc.constraint)
			cstest.RequireErrorContains(t, err, tc.wantErr)
			require.Equal(t, tc.want, actual)
		})
	}
}
