package apiserver

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// certReloadInterval bounds how often the certificate files are read again.
// Renewal happens hours before expiry, so a few seconds of delay cost nothing.
const certReloadInterval = 10 * time.Second

// certReloader hands out the LAPI's server certificate and picks up a new
// one when the files change on disk. Short-lived certificates renewed in
// place (Kubernetes pod certificates, cert-manager Secrets) are then served
// without a restart or SIGHUP.
type certReloader struct {
	certFile string
	keyFile  string
	interval time.Duration
	now      func() time.Time

	mu          sync.Mutex
	cert        *tls.Certificate
	certPEM     []byte
	keyPEM      []byte
	checkedAt   time.Time
	lastWarning string
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
		interval: certReloadInterval,
		now:      time.Now,
	}

	certPEM, keyPEM, err := r.read()
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("while loading TLS key pair: %w", err)
	}

	r.cert, r.certPEM, r.keyPEM, r.checkedAt = &cert, certPEM, keyPEM, r.now()

	return r, nil
}

func (r *certReloader) read() ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("while reading TLS cert file: %w", err)
	}

	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("while reading TLS key file: %w", err)
	}

	return certPEM, keyPEM, nil
}

// GetCertificate is meant for tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()

	now := r.now()
	if now.Sub(r.checkedAt) < r.interval {
		cert := r.cert
		r.mu.Unlock()

		return cert, nil
	}

	// Claim this check before reading, so concurrent handshakes keep being
	// served from memory while one of them reads the files.
	r.checkedAt = now
	r.mu.Unlock()

	certPEM, keyPEM, err := r.read()

	r.mu.Lock()
	defer r.mu.Unlock()

	if err != nil {
		r.warnOnce("keeping the current TLS certificate: %s", err)
		return r.cert, nil
	}

	if bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM) {
		r.lastWarning = ""
		return r.cert, nil
	}

	// A pair that does not parse is usually one caught halfway through a
	// renewal (cert written, key not yet). Serve the old one and try again
	// after the interval.
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		r.warnOnce("keeping the current TLS certificate, the new pair does not load: %s", err)
		return r.cert, nil
	}

	log.Infof("(tls) reloaded server certificate from %s", r.certFile)

	r.cert, r.certPEM, r.keyPEM, r.lastWarning = &cert, certPEM, keyPEM, ""

	return r.cert, nil
}

// warnOnce logs a warning unless it is the one logged last, so a file that
// stays broken does not repeat the same line every interval. Callers hold mu.
func (r *certReloader) warnOnce(format string, err error) {
	msg := fmt.Sprintf(format, err)
	if msg == r.lastWarning {
		return
	}

	r.lastWarning = msg
	log.Warn(msg)
}
