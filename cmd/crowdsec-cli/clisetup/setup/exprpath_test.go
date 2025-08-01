package setup

import (
	"runtime"
	"testing"

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
		e := OSExprPath{}

		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			actual := e.Exists(ctx, tc.path)
			require.Equal(t, tc.want, actual)
		})
	}
}
