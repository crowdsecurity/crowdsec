package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

func TestNotifyTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	tests := []struct {
		name         string
		extra        string
		configureErr string
		notifyErr    string
	}{
		{
			name:      "untrusted certificate is rejected by default",
			notifyErr: "certificate signed by unknown authority",
		},
		{
			name:  "custom CA",
			extra: "ca_cert_path: " + caPath,
		},
		{
			name:  "skip verification",
			extra: "skip_tls_verification: true",
		},
		{
			name:         "missing CA file",
			extra:        "ca_cert_path: " + filepath.Join(t.TempDir(), "nope.pem"),
			configureErr: "unable to load CA certificate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			s := &Splunk{PluginConfigByName: make(map[string]PluginConfig)}

			cfg := fmt.Sprintf("name: test\nurl: %s\ntoken: x\n%s\n", srv.URL, tc.extra)

			_, err := s.Configure(ctx, &protobufs.Config{Config: []byte(cfg)})
			if tc.configureErr != "" {
				require.ErrorContains(t, err, tc.configureErr)
				return
			}

			require.NoError(t, err)

			_, err = s.Notify(ctx, &protobufs.Notification{Name: "test", Text: "{}"})
			if tc.notifyErr != "" {
				require.ErrorContains(t, err, tc.notifyErr)
				return
			}

			require.NoError(t, err)
		})
	}
}
