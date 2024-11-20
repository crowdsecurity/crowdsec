package v1

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type CRLChecker struct {
	path     string                 // path to the CRL file
	fileInfo os.FileInfo            // last stat of the CRL file
	crls     []*x509.RevocationList // parsed CRLs
	logger   *log.Entry
	mu       sync.RWMutex
	lastLoad time.Time // time when the CRL file was last read successfully
	onLoad   func()    // called when the CRL file changes (and is read successfully)
}

func NewCRLChecker(crlPath string, onLoad func(), logger *log.Entry) (*CRLChecker, error) {
	cc := &CRLChecker{
		path:   crlPath,
		logger: logger,
		onLoad: onLoad,
	}

	err := cc.refresh()
	if err != nil {
		return nil, err
	}

	return cc, nil
}

func (*CRLChecker) decodeCRLs(content []byte) ([]*x509.RevocationList, error) {
	var crls []*x509.RevocationList

	for {
		block, rest := pem.Decode(content)
		if block == nil {
			break // no more PEM blocks
		}

		content = rest

		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			// invalidate the whole CRL file so we can still use the previous version
			return nil, fmt.Errorf("could not parse file: %w", err)
		}

		crls = append(crls, crl)
	}

	return crls, nil
}

// refresh() reads the CRL file if new or changed since the last time
func (cc *CRLChecker) refresh() error {
	// noop if lastLoad is less than 5 seconds ago
	if time.Since(cc.lastLoad) < 5*time.Second {
		return nil
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.logger.Debugf("loading CRL file from %s", cc.path)

	fileInfo, err := os.Stat(cc.path)
	if err != nil {
		return fmt.Errorf("could not access CRL file: %w", err)
	}

	// noop if the file didn't change
	if cc.fileInfo != nil && fileInfo.ModTime().Equal(cc.fileInfo.ModTime()) && fileInfo.Size() == cc.fileInfo.Size() {
		return nil
	}

	// the encoding/pem package wants bytes, not io.Reader
	crlContent, err := os.ReadFile(cc.path)
	if err != nil {
		return fmt.Errorf("could not read CRL file: %w", err)
	}

	cc.crls, err = cc.decodeCRLs(crlContent)
	if err != nil {
		return err
	}

	cc.fileInfo = fileInfo
	cc.lastLoad = time.Now()
	cc.onLoad()

	return nil
}

// isRevoked checks if the client certificate is revoked by any of the CRL blocks
// It returns a boolean indicating if the certificate is revoked and a boolean indicating
// if the CRL check was successful and could be cached.
func (cc *CRLChecker) isRevokedBy(cert *x509.Certificate, issuer *x509.Certificate) (bool, bool) {
	if cc == nil {
		return false, true
	}

	err := cc.refresh()
	if err != nil {
		// we can't quit obviously, so we just log the error and continue
		// but we can assume we have loaded a CRL, or it would have quit the first time
		cc.logger.Errorf("while refreshing CRL: %s - will keep using CRL file read at %s", err,
			cc.lastLoad.Format(time.RFC3339))
	}

	now := time.Now().UTC()

	cc.mu.RLock()
	defer cc.mu.RUnlock()

	for _, crl := range cc.crls {
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			continue
		}

		if now.After(crl.NextUpdate) {
			cc.logger.Warn("CRL has expired, will still validate the cert against it.")
		}

		if now.Before(crl.ThisUpdate) {
			cc.logger.Warn("CRL is not yet valid, will still validate the cert against it.")
		}

		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				cc.logger.Warn("client certificate is revoked by CRL")
				return true, true
			}
		}
	}

	return false, true
}
