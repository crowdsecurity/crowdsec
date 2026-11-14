package clilapi

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func configWithMissingCredentialsFile(t *testing.T) *csconfig.Config {
	t.Helper()

	return &csconfig.Config{
		API: &csconfig.APICfg{
			Client: &csconfig.LocalApiClientCfg{
				CredentialsFilePath: filepath.Join(t.TempDir(), "does-not-exist", "credentials.yaml"),
			},
		},
	}
}

// A missing credentials file must not prevent "lapi register" from running,
// because creating that file is the command's purpose.
func TestRegisterWithoutCredentialsFile(t *testing.T) {
	cfg := configWithMissingCredentialsFile(t)

	cmd := New(func() *csconfig.Config { return cfg }).NewCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"register", "--machine", "testmachine", "--url", "http://127.0.0.1:1", "--token", "testtoken"})

	err := cmd.Execute()

	// The command gets past credentials loading and fails only when it
	// actually talks to the (unreachable) API.
	require.ErrorContains(t, err, "api client register")
	require.NotContains(t, err.Error(), "loading api client")
}

// Subcommands that read the LAPI still require an existing credentials file.
func TestStatusStillRequiresCredentialsFile(t *testing.T) {
	cfg := configWithMissingCredentialsFile(t)

	cmd := New(func() *csconfig.Config { return cfg }).NewCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"status"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "loading api client")
}
