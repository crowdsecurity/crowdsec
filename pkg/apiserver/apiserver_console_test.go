package apiserver

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
)

const unenrolledConsoleMsg = "Machine is not enrolled in the console, can't synchronize with the console"

// TestNewServerConsoleEnrollmentLogLevel covers #4809: with CAPI enabled but the
// machine not enrolled in the console, starting the server must not log at
// error level — enrollment is optional, so the message is a warning at most.
func TestNewServerConsoleEnrollmentLogLevel(t *testing.T) {
	tests := []struct {
		name        string
		enrolled    bool
		wantWarning bool
	}{
		{
			name:        "unenrolled machine logs a warning, not an error",
			enrolled:    false,
			wantWarning: true,
		},
		{
			name:        "enrolled machine logs nothing about enrollment",
			enrolled:    true,
			wantWarning: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			config := LoadTestConfig(t)

			// Seed a CAPI token so NewAPIC authenticates from the DB instead
			// of talking to the network. The token carries no
			// organization_id claim unless the machine is enrolled.
			claims := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
			if tc.enrolled {
				claims["organization_id"] = "test-org"
			}

			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret"))
			require.NoError(t, err)

			dbClient, err := database.NewClient(ctx, config.API.Server.DbConfig, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = dbClient.Close() })

			require.NoError(t, dbClient.SaveAPICToken(ctx, token))

			config.API.Server.OnlineClient = &csconfig.OnlineApiClientCfg{
				Credentials: &csconfig.ApiCredentialsCfg{
					URL:      "https://api.crowdsec.net/",
					PapiURL:  "https://api.crowdsec.net/",
					Login:    "test-machine",
					Password: "test-password",
				},
				PullConfig: csconfig.CapiPullConfig{
					Community:  new(bool),
					Blocklists: new(bool),
				},
				Sharing: new(bool),
			}

			hook := logtest.NewGlobal()
			t.Cleanup(hook.Reset)

			logger, _ := logtest.NewNullLogger()

			_, err = NewServer(ctx, config.API.Server, logger.WithFields(nil))
			require.NoError(t, err)

			var errors, warnings int

			for _, e := range hook.AllEntries() {
				if e.Message != unenrolledConsoleMsg {
					continue
				}

				switch e.Level {
				case log.ErrorLevel:
					errors++
				case log.WarnLevel:
					warnings++
				}
			}

			require.Zero(t, errors, "unenrolled-console message must not be logged at error level")

			if tc.wantWarning {
				require.Equal(t, 1, warnings, "unenrolled-console message must be logged once at warning level")
			} else {
				require.Zero(t, warnings, "enrolled machine must not log the unenrolled-console message")
			}
		})
	}
}
