package cstest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func AssertErrorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		assert.ErrorContains(t, err, expectedErr)
		return
	}

	assert.NoError(t, err)
}

func RequireErrorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		require.ErrorContains(t, err, expectedErr)
		return
	}

	require.NoError(t, err)
}
