package cliallowlists

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

//nolint:gosmopolitan // Exercise the CLI's process-local display timezone.
func TestAllowlistTimestamps(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	require.NoError(t, err)
	// Restore the process timezone after this nonparallel test.
	previousLocation := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previousLocation })

	const fixture = `{"name":"example","created_at":"2026-07-15T12:34:56Z","updated_at":"2026-07-15T13:34:56Z","items":[
		{"value":"192.0.2.1","created_at":"2026-07-15T14:34:56Z","expiration":"2026-07-15T15:34:56Z"},
		{"value":"192.0.2.2","created_at":"2026-07-15T14:34:56Z"}]}`
	transport := httpmock.NewMockTransport()
	transport.RegisterResponder(http.MethodGet, "http://lapi/v1/allowlists", httpmock.NewStringResponder(http.StatusOK, "["+fixture+"]"))
	transport.RegisterResponder(http.MethodGet, "http://lapi/v1/allowlists/example", httpmock.NewStringResponder(http.StatusOK, fixture))
	client, err := apiclient.NewDefaultClient(&url.URL{Scheme: "http", Host: "lapi", Path: "/"}, "v1", "test", &http.Client{Transport: transport})
	require.NoError(t, err)
	cfg := &csconfig.Config{Cscli: &csconfig.CscliCfg{Color: "no"}}
	cli := New(func() *csconfig.Config { return cfg })

	for _, format := range []string{"human", "json", "raw"} {
		t.Run(format, func(t *testing.T) {
			cfg.Cscli.Output = format
			var list, inspect bytes.Buffer
			require.NoError(t, cli.list(t.Context(), client, &list))
			require.NoError(t, cli.inspect(t.Context(), client, "example", &inspect))
			if format == "human" {
				require.Contains(t, list.String(), "2026-07-15T14:34:56.000+02:00")
				require.Contains(t, list.String(), "2026-07-15T15:34:56.000+02:00")
				require.Contains(t, inspect.String(), "2026-07-15T14:34:56.000+02:00")
				require.Contains(t, inspect.String(), "2026-07-15T15:34:56.000+02:00")
				require.Contains(t, inspect.String(), "2026-07-15T16:34:56+02:00")
				require.Contains(t, inspect.String(), "2026-07-15T17:34:56.000+02:00")
				require.Contains(t, inspect.String(), "never")
			} else {
				require.Contains(t, list.String(), "2026-07-15T12:34:56")
				require.Contains(t, inspect.String(), "2026-07-15T15:34:56")
				require.NotContains(t, list.String()+inspect.String(), "+02:00")
			}
		})
	}
}
