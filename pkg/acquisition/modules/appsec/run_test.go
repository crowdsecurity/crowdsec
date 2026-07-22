package appsecacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"
)

func TestSource_listenAndServe(t *testing.T) {
	tests := []struct {
		name          string
		clientCrtPath string
		clientKeyPath string
		useSocket     bool
		wantErr       bool
	}{
		{
			name:          "Test TCP server with trust client cert",
			clientCrtPath: "testdata/client.crt",
			clientKeyPath: "testdata/client.key",
			useSocket:     false,
			wantErr:       false,
		},
		{
			name:          "Test TCP server with untrust client cert",
			clientCrtPath: "testdata/selfsined-client.crt",
			clientKeyPath: "testdata/selfsined-client.key",
			useSocket:     false,
			wantErr:       true,
		},
		{
			name:          "Test Socket server with trust client cert",
			clientCrtPath: "testdata/client.crt",
			clientKeyPath: "testdata/client.key",
			useSocket:     true,
			wantErr:       false,
		},
		{
			name:          "Test Socket server with untrust client cert",
			clientCrtPath: "testdata/selfsined-client.crt",
			clientKeyPath: "testdata/selfsined-client.key",
			useSocket:     true,
			wantErr:       true,
		},
	}

	tempDir := t.TempDir()
	socketFile := filepath.Join(tempDir, "test.sock")
	url := "https://127.0.0.1:7422"

	config := &Configuration{
		ListenAddr:   "127.0.0.1:7422",
		ListenSocket: socketFile,
		TLSAuth:      true,
		CertFilePath: "testdata/server.crt",
		KeyFilePath:  "testdata/server.key",
		CaCertPath:   "testdata/ca.crt",
	}
	runner := make([]AppsecRunner, 0)
	tt := &tomb.Tomb{}

	logger := logrus.New()
	// Disable output
	logger.SetOutput(io.Discard)
	// Create Entry from disabled loggger
	testLogger := logrus.NewEntry(logger)

	w := &Source{AppsecRunners: runner, config: *config, logger: testLogger}

	err := w.configureHTTPServer()
	require.NoError(t, err)

	// Supress server TLS error messages
	w.server.ErrorLog = log.New(io.Discard, "", 0)

	w.mux.HandleFunc("/test", func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	tt.Go(func() error {
		err := w.listenAndServe(context.Background(), tt)
		require.NoError(t, err)
		return nil
	})

	time.Sleep(1 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// init client cert
			cert, err := tls.LoadX509KeyPair(tt.clientCrtPath, tt.clientKeyPath)
			require.NoError(t, err)

			caCert, err := os.ReadFile("testdata/ca.crt")
			require.NoError(t, err)

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			}

			dialer := &net.Dialer{}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}

			if tt.useSocket {
				client = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: tlsConfig,
						DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
							return dialer.DialContext(ctx, "unix", socketFile)
						},
					},
				}
			}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("%s/test", url), http.NoBody)
			require.NoError(t, err)

			resp, err := client.Do(req)

			if tt.wantErr {
				require.ErrorContains(t, err, "tls: certificate required")
			} else {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	}

	w.server.Close()
	tt.Kill(nil)
	err = tt.Wait()
	require.NoError(t, err)
}
