package apiserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writePair writes a self-signed certificate with the given serial and its
// key to dir, and returns the PEM bytes of both.
func writePair(t *testing.T, dir string, serial int64) ([]byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "lapi"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600))

	return certPEM, keyPEM
}

func servedSerial(t *testing.T, r *certReloader) int64 {
	t.Helper()

	cert, err := r.GetCertificate(nil)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	return leaf.SerialNumber.Int64()
}

func TestCertReloader(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, dir string)
		wait   time.Duration
		want   int64
	}{
		{
			name:   "unchanged files keep the certificate",
			change: func(*testing.T, string) {},
			wait:   time.Minute,
			want:   1,
		},
		{
			name:   "renewed pair is picked up after the interval",
			change: func(t *testing.T, dir string) { writePair(t, dir, 2) },
			wait:   certReloadInterval,
			want:   2,
		},
		{
			name:   "renewed pair is not read again before the interval",
			change: func(t *testing.T, dir string) { writePair(t, dir, 2) },
			wait:   certReloadInterval - time.Second,
			want:   1,
		},
		{
			name: "half-written renewal keeps the old certificate",
			change: func(t *testing.T, dir string) {
				// new cert, old key: the pair does not match
				other := t.TempDir()
				certPEM, _ := writePair(t, other, 3)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600))
			},
			wait: certReloadInterval,
			want: 1,
		},
		{
			name: "missing files keep the old certificate",
			change: func(t *testing.T, dir string) {
				require.NoError(t, os.Remove(filepath.Join(dir, "tls.key")))
			},
			wait: certReloadInterval,
			want: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writePair(t, dir, 1)

			r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
			require.NoError(t, err)

			clock := time.Now()
			r.now = func() time.Time { return clock }
			r.checkedAt = clock

			require.Equal(t, int64(1), servedSerial(t, r))

			tc.change(t, dir)
			clock = clock.Add(tc.wait)

			require.Equal(t, tc.want, servedSerial(t, r))
		})
	}
}

func TestCertReloaderMissingFilesAtStart(t *testing.T) {
	dir := t.TempDir()

	_, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	require.ErrorContains(t, err, "while reading TLS cert file")
}

// TestCertReloaderServesRenewedCertificate runs a real TLS listener the way
// the LAPI does (ServeTLS with empty file names and GetCertificate set) and
// checks the handshake before and after the files are replaced.
func TestCertReloaderServesRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, 1)

	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	require.NoError(t, err)

	clock := time.Now()
	r.now = func() time.Time { return clock }
	r.checkedAt = clock

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{
		Handler:           http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		TLSConfig:         &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: time.Second,
	}

	go func() { _ = srv.ServeTLS(listener, "", "") }()

	t.Cleanup(func() { _ = srv.Close() })

	handshake := func() int64 {
		conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test inspects the served leaf, it does not trust it
		require.NoError(t, err)

		defer conn.Close()

		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}

	require.Equal(t, int64(1), handshake())

	writePair(t, dir, 2)
	clock = clock.Add(certReloadInterval)

	require.Equal(t, int64(2), handshake())
}

func TestCertReloaderWarnsOncePerError(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)

	dir := t.TempDir()
	writePair(t, dir, 1)

	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	require.NoError(t, err)

	clock := time.Now()
	r.now = func() time.Time { return clock }
	r.checkedAt = clock

	warnings := func() int {
		n := 0

		for _, e := range hook.AllEntries() {
			if e.Level == log.WarnLevel {
				n++
			}
		}

		return n
	}

	require.NoError(t, os.Remove(filepath.Join(dir, "tls.key")))

	for range 5 {
		clock = clock.Add(certReloadInterval)
		require.Equal(t, int64(1), servedSerial(t, r))
	}

	require.Equal(t, 1, warnings(), "the same broken file is reported once")

	// a different error is reported again
	other := t.TempDir()
	_, keyPEM := writePair(t, other, 9)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600))

	clock = clock.Add(certReloadInterval)
	require.Equal(t, int64(1), servedSerial(t, r))
	require.Equal(t, 2, warnings(), "a new error is reported")
}

// TestCertReloaderConcurrentHandshakes runs many handshakes while the files
// are renewed; run with -race. Every caller gets a certificate, and the new
// one is served afterwards.
func TestCertReloaderConcurrentHandshakes(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, 1)

	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	require.NoError(t, err)

	var clock atomic.Int64

	clock.Store(time.Now().UnixNano())
	r.now = func() time.Time { return time.Unix(0, clock.Load()) }
	r.checkedAt = r.now()

	writePair(t, dir, 2)
	clock.Add(int64(certReloadInterval))

	var wg sync.WaitGroup

	for range 50 {
		wg.Go(func() {
			cert, err := r.GetCertificate(nil)
			assert.NoError(t, err)
			assert.NotNil(t, cert)
		})
	}

	wg.Wait()

	require.Equal(t, int64(2), servedSerial(t, r))
}
