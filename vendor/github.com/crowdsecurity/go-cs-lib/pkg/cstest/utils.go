package cstest

import (
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	logtest "github.com/sirupsen/logrus/hooks/test"
)

func AssertErrorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		assert.ErrorContains(t, err, expectedErr)
		return
	}

	assert.NoError(t, err)
}

func AssertErrorMessage(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		errmsg := ""
		if err != nil {
			errmsg = err.Error()
		}
		assert.Equal(t, expectedErr, errmsg)
		return
	}

	require.NoError(t, err)
}

func RequireErrorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		require.ErrorContains(t, err, expectedErr)
		return
	}

	require.NoError(t, err)
}

func RequireErrorMessage(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		errmsg := ""
		if err != nil {
			errmsg = err.Error()
		}
		require.Equal(t, expectedErr, errmsg)
		return
	}

	require.NoError(t, err)
}

func RequireLogContains(t *testing.T, hook *logtest.Hook, expected string) {
	t.Helper()

	// look for a log entry that matches the expected message
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, expected) {
			return
		}
	}

	// show all hook entries, in case the test fails we'll need them
	for _, entry := range hook.AllEntries() {
		t.Logf("log entry: %s", entry.Message)
	}

	require.Fail(t, "no log entry found with message", expected)
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
