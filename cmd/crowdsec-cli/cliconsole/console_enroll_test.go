package cliconsole

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func TestEnrollDeletesCachedToken(t *testing.T) {
	tests := []struct {
		name         string
		enrollStatus int
		enrollBody   string
		quick        bool
		wantErr      bool
		wantDeleted  bool
	}{
		{
			name:         "quick enroll: link created",
			enrollStatus: http.StatusCreated,
			enrollBody:   `{"url":"https://app.crowdsec.net/quick-enroll?token=x","expires_at":4102444800000}`,
			quick:        true,
			wantDeleted:  true,
		},
		{
			name:         "enroll with key: accepted",
			enrollStatus: http.StatusCreated,
			enrollBody:   `{}`,
			wantDeleted:  true,
		},
		{
			name:         "already enrolled: token kept",
			enrollStatus: http.StatusOK,
			enrollBody:   `{}`,
		},
		{
			name:         "bad key: token kept",
			enrollStatus: http.StatusForbidden,
			enrollBody:   `{"message":"the attachment key provided is not valid"}`,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			mux := http.NewServeMux()
			mux.HandleFunc("/v3/watchers/login", func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, `{"code":200,"expire":"2099-01-01T00:00:00Z","token":"fresh"}`)
			})
			mux.HandleFunc("/v3/watchers/enroll", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.enrollStatus)
				fmt.Fprint(w, tc.enrollBody)
			})

			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			cfg, db := enrollTestConfig(t, srv.URL+"/")

			require.NoError(t, db.SaveAPICToken(ctx, "cached"))

			cli := New(func() *csconfig.Config { return cfg })

			key := "key"
			if tc.quick {
				key = ""
			}

			err := cli.enroll(ctx, key, "", false, nil, nil, tc.quick)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			_, err = db.LoadAPICToken(ctx, nil)
			if tc.wantDeleted {
				require.ErrorIs(t, err, database.ErrTokenNotFound)
			} else {
				// "cached" isn't a JWT: it's still there if parsing it is what fails
				require.ErrorIs(t, err, database.ErrTokenParse)
			}
		})
	}
}

func enrollTestConfig(t *testing.T, capiURL string) (*csconfig.Config, *database.Client) {
	t.Helper()

	dir := t.TempDir()

	indexFile := filepath.Join(dir, ".index.json")
	require.NoError(t, os.WriteFile(indexFile, []byte("{}"), 0o600))

	dbCfg := &csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: filepath.Join(dir, "crowdsec.db"),
	}

	db, err := database.NewClient(t.Context(), dbCfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	cfg := &csconfig.Config{
		DbConfig: dbCfg,
		Hub: &csconfig.LocalHubCfg{
			HubIndexFile:   indexFile,
			HubDir:         dir,
			InstallDir:     dir,
			InstallDataDir: dir,
		},
		API: &csconfig.APICfg{
			Server: &csconfig.LocalApiServerCfg{
				ConsoleConfig:     &csconfig.ConsoleConfig{},
				ConsoleConfigPath: filepath.Join(dir, "console.yaml"),
				OnlineClient: &csconfig.OnlineApiClientCfg{
					Credentials: &csconfig.ApiCredentialsCfg{
						URL:      capiURL,
						Login:    "login",
						Password: "password",
					},
				},
			},
		},
	}

	return cfg, db
}
