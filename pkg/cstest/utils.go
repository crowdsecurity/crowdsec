package cstest

import (
	"strings"
	"testing"
	"text/template"

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

// Interpolate fills a string template with the given values, can be map or struct.
// example: Interpolate("{{.Name}}", map[string]string{"Name": "JohnDoe"})
func Interpolate(s string, data interface{}) (string, error) {
	tmpl, err := template.New("").Parse(s)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	err = tmpl.Execute(&b, data)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}
