package clialert

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

//nolint:gosmopolitan // Machine-readable output must not follow the process timezone.
func TestAlertMachineReadableTimestamps(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	require.NoError(t, err)
	output, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)
	// Capture the command's stdout and restore process globals after this nonparallel test.
	previousLocation, previousOutput := time.Local, os.Stdout
	time.Local, os.Stdout = location, output
	t.Cleanup(func() {
		time.Local, os.Stdout = previousLocation, previousOutput
		require.NoError(t, output.Close())
	})

	const fixture = `{"id":1,"created_at":"2026-07-15T12:34:56Z","start_at":"2026-07-15T11:34:56Z","stop_at":"2026-07-15T12:34:56Z",
		"scenario":"example","source":{"scope":"ip","value":"192.0.2.1"},"events":[{"timestamp":"2026-07-15T11:34:56Z"}]}`
	transport := httpmock.NewMockTransport()
	transport.RegisterResponder(http.MethodGet, "http://lapi/v1/alerts/1", httpmock.NewStringResponder(http.StatusOK, fixture))
	transport.RegisterResponder(http.MethodGet, "http://lapi/v1/alerts", httpmock.NewStringResponder(http.StatusOK, "["+fixture+"]"))
	client, err := apiclient.NewDefaultClient(&url.URL{Scheme: "http", Host: "lapi", Path: "/"}, "v1", "test", &http.Client{Transport: transport})
	require.NoError(t, err)
	cfg := &csconfig.Config{Cscli: &csconfig.CscliCfg{}}
	cli := New(func() *csconfig.Config { return cfg })
	cli.client = client

	for _, format := range []string{"json", "raw"} {
		for _, command := range []string{"list", "inspect"} {
			t.Run(command+"/"+format, func(t *testing.T) {
				cfg.Cscli.Output = format
				require.NoError(t, output.Truncate(0))
				_, err := output.Seek(0, io.SeekStart)
				require.NoError(t, err)
				if command == "list" {
					require.NoError(t, cli.list(t.Context(), apiclient.AlertsListOpts{IncludeCAPI: new(false)}, nil, nil, false))
				} else {
					require.NoError(t, cli.inspect(t.Context(), true, "1"))
				}
				_, err = output.Seek(0, io.SeekStart)
				require.NoError(t, err)
				encoded, err := io.ReadAll(output)
				require.NoError(t, err)
				require.Contains(t, string(encoded), "2026-07-15T12:34:56Z")
				require.NotContains(t, string(encoded), "+02:00")
			})
		}
	}
}
