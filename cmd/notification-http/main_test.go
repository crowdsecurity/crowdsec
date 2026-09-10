package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

func generateTestPKI(t *testing.T, dir string) (caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath string) {
	t.Helper()

	// CA key and cert
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCertPath = filepath.Join(dir, "ca.crt")
	caCertFile, err := os.Create(caCertPath)
	require.NoError(t, err)
	defer caCertFile.Close()
	require.NoError(t, pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}))

	// Server cert and key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	serverCertPath = filepath.Join(dir, "server.crt")
	serverCertFile, err := os.Create(serverCertPath)
	require.NoError(t, err)
	defer serverCertFile.Close()
	require.NoError(t, pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}))

	serverKeyPath = filepath.Join(dir, "server.key")
	serverKeyFile, err := os.Create(serverKeyPath)
	require.NoError(t, err)
	defer serverKeyFile.Close()
	require.NoError(t, pem.Encode(serverKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}))

	// Client cert and key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "client",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCertPath = filepath.Join(dir, "client.crt")
	clientCertFile, err := os.Create(clientCertPath)
	require.NoError(t, err)
	defer clientCertFile.Close()
	require.NoError(t, pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}))

	clientKeyPath = filepath.Join(dir, "client.key")
	clientKeyFile, err := os.Create(clientKeyPath)
	require.NoError(t, err)
	defer clientKeyFile.Close()
	require.NoError(t, pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}))

	return caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath
}

func TestConfigureAndNotifyMTLS(t *testing.T) {
	tempDir := t.TempDir()
	caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath := generateTestPKI(t, tempDir)

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	require.NoError(t, err)

	clientCAs := x509.NewCertPool()
	caBytes, err := os.ReadFile(caCertPath)
	require.NoError(t, err)
	clientCAs.AppendCertsFromPEM(caBytes)

	receivedBody := make(chan string, 1)

	// Create a TLS server requiring client cert
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NotEmpty(t, r.TLS.PeerCertificates)
		require.Equal(t, "client", r.TLS.PeerCertificates[0].Subject.CommonName)
		bodyBytes := make([]byte, 1024)
		n, _ := r.Body.Read(bodyBytes)
		receivedBody <- string(bodyBytes[:n])
		w.WriteHeader(http.StatusOK)
	}))

	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	ts.StartTLS()
	defer ts.Close()

	t.Run("Valid mTLS connection succeeds", func(t *testing.T) {
		cfg := PluginConfig{
			Name:         "test_mtls",
			URL:          ts.URL,
			Method:       http.MethodPost,
			CertPath:     clientCertPath,
			KeyPath:      clientKeyPath,
			CAPath:       caCertPath,
			LogLevel:     "debug",
		}
		rawCfg, err := yaml.Marshal(cfg)
		require.NoError(t, err)

		plugin := &HTTPPlugin{PluginConfigByName: make(map[string]PluginConfig)}
		_, err = plugin.Configure(context.Background(), &protobufs.Config{Config: rawCfg})
		require.NoError(t, err)

		_, err = plugin.Notify(context.Background(), &protobufs.Notification{
			Name: "test_mtls",
			Text: "hello mtls",
		})
		require.NoError(t, err)

		select {
		case body := <-receivedBody:
			require.Equal(t, "hello mtls", body)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for request")
		}
	})

	t.Run("Missing client key error", func(t *testing.T) {
		cfg := PluginConfig{
			Name:         "test_missing_key",
			URL:          ts.URL,
			Method:       http.MethodPost,
			CertPath:     clientCertPath,
			KeyPath:      filepath.Join(tempDir, "nonexistent.key"),
			CAPath:       caCertPath,
		}
		rawCfg, err := yaml.Marshal(cfg)
		require.NoError(t, err)

		plugin := &HTTPPlugin{PluginConfigByName: make(map[string]PluginConfig)}
		_, err = plugin.Configure(context.Background(), &protobufs.Config{Config: rawCfg})
		require.Error(t, err)
	})

	t.Run("One of cert_path or key_path specified without the other", func(t *testing.T) {
		cfg := PluginConfig{
			Name:     "test_only_cert",
			URL:      ts.URL,
			Method:   http.MethodPost,
			CertPath: clientCertPath,
			CAPath:   caCertPath,
		}
		rawCfg, err := yaml.Marshal(cfg)
		require.NoError(t, err)

		plugin := &HTTPPlugin{PluginConfigByName: make(map[string]PluginConfig)}
		_, err = plugin.Configure(context.Background(), &protobufs.Config{Config: rawCfg})
		require.Error(t, err)
	})
}
