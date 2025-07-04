package setup

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/stretchr/testify/require"
)

func TestPathExists(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	type test struct {
		path string
		want bool
	}

	tests := []test{
		{"/this-should-not-exist", false},
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, test{`C:\`, true})
	} else {
		tests = append(tests, test{"/tmp", true})
	}

	for _, tc := range tests {
		env := NewExprEnvironment(ctx, ExprOS{}, &ExprState{}, OSPathChecker{})

		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			actual := env.PathExists(ctx, tc.path)
			require.Equal(t, tc.want, actual)
		})
	}
}

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
		e := ExprOS{RawVersion: tc.version}

		t.Run(fmt.Sprintf("Check(%s,%s)", tc.version, tc.constraint), func(t *testing.T) {
			t.Parallel()

			actual, err := e.VersionCheck(tc.constraint)
			cstest.RequireErrorContains(t, err, tc.wantErr)
			require.Equal(t, tc.want, actual)
		})
	}
}

func TestUnitFound(t *testing.T) {
	ctx := t.Context()

	state := NewExprState(DetectOptions{}, UnitMap{"crowdsec-setup-installed.service": struct{}{}}, nil)
	env := NewExprEnvironment(ctx, ExprOS{}, state, nil)

	installed, err := env.UnitFound(ctx, "crowdsec-setup-installed.service")
	require.NoError(t, err)
	require.True(t, installed)

	installed, err = env.UnitFound(ctx, "crowdsec-setup-missing.service")
	require.NoError(t, err)
	require.False(t, installed)
}
