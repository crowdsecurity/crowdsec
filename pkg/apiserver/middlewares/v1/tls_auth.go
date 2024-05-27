package v1

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type TLSAuth struct {
	AllowedOUs      []string
	CrlPath         string
	revocationCache map[string]cacheEntry
	cacheExpiration time.Duration
	logger          *log.Entry
}

type cacheEntry struct {
	revoked   bool
	timestamp time.Time
}

func (ta *TLSAuth) ocspQuery(server string, cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		ta.logger.Errorf("TLSAuth: error creating OCSP request: %s", err)
		return nil, err
	}

	httpRequest, err := http.NewRequest(http.MethodPost, server, bytes.NewBuffer(req))
	if err != nil {
		ta.logger.Error("TLSAuth: cannot create HTTP request for OCSP")
		return nil, err
	}

	ocspURL, err := url.Parse(server)
	if err != nil {
		ta.logger.Error("TLSAuth: cannot parse OCSP URL")
		return nil, err
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)

	httpClient := &http.Client{}

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		ta.logger.Error("TLSAuth: cannot send HTTP request to OCSP")
		return nil, err
	}
	defer httpResponse.Body.Close()

	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		ta.logger.Error("TLSAuth: cannot read HTTP response from OCSP")
		return nil, err
	}

	ocspResponse, err := ocsp.ParseResponseForCert(output, cert, issuer)

	return ocspResponse, err
}

func (ta *TLSAuth) isExpired(cert *x509.Certificate) bool {
	now := time.Now().UTC()

	if cert.NotAfter.UTC().Before(now) {
		ta.logger.Errorf("TLSAuth: client certificate is expired (NotAfter: %s)", cert.NotAfter.UTC())
		return true
	}

	if cert.NotBefore.UTC().After(now) {
		ta.logger.Errorf("TLSAuth: client certificate is not yet valid (NotBefore: %s)", cert.NotBefore.UTC())
		return true
	}

	return false
}

// isOCSPRevoked checks if the client certificate is revoked by any of the OCSP servers present in the certificate.
// It returns a boolean indicating if the certificate is revoked and a boolean indicating if the OCSP check was successful and could be cached.
func (ta *TLSAuth) isOCSPRevoked(cert *x509.Certificate, issuer *x509.Certificate) (bool, bool) {
	if cert.OCSPServer == nil || len(cert.OCSPServer) == 0 {
		ta.logger.Infof("TLSAuth: no OCSP Server present in client certificate, skipping OCSP verification")
		return false, true
	}

	for _, server := range cert.OCSPServer {
		ocspResponse, err := ta.ocspQuery(server, cert, issuer)
		if err != nil {
			ta.logger.Errorf("TLSAuth: error querying OCSP server %s: %s", server, err)
			continue
		}

		switch ocspResponse.Status {
		case ocsp.Good:
			return false, true
		case ocsp.Revoked:
			ta.logger.Errorf("TLSAuth: client certificate is revoked by server %s", server)
			return true, true
		case ocsp.Unknown:
			log.Debugf("unknow OCSP status for server %s", server)
			continue
		}
	}

	log.Infof("Could not get any valid OCSP response, assuming the cert is revoked")

	return true, false
}

func decodeCRLs(content []byte, logger *log.Entry) []*x509.RevocationList {
	var crls []*x509.RevocationList

	for {
		block, rest := pem.Decode(content)
		if block == nil {
			break // no more PEM blocks
		}

		content = rest

		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			logger.Errorf("could not parse a PEM block in CRL file, skipping: %s", err)
			continue
		}

		crls = append(crls, crl)
	}

	return crls
}

// isCRLRevoked checks if the client certificate is revoked by the CRL present in the CrlPath.
// It returns a boolean indicating if the certificate is revoked and a boolean indicating
// if the CRL check was successful and could be cached.
func (ta *TLSAuth) isCRLRevoked(cert *x509.Certificate) (bool, bool) {
	if ta.CrlPath == "" {
		ta.logger.Info("no crl_path, skipping CRL check")
		return false, true
	}

	crlContent, err := os.ReadFile(ta.CrlPath)
	if err != nil {
		ta.logger.Errorf("could not read CRL file, skipping check: %s", err)
		return false, false
	}

	crls := decodeCRLs(crlContent, ta.logger)
	now := time.Now().UTC()

	for _, crl := range crls {
		if now.After(crl.NextUpdate) {
			ta.logger.Warn("CRL has expired, will still validate the cert against it.")
		}

		if now.Before(crl.ThisUpdate) {
			ta.logger.Warn("CRL is not yet valid, will still validate the cert against it.")
		}

		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				ta.logger.Warn("client certificate is revoked by CRL")
				return true, true
			}
		}
	}

	return false, true
}

func (ta *TLSAuth) isRevoked(cert *x509.Certificate, issuer *x509.Certificate) (bool, error) {
	sn := cert.SerialNumber.String()
	if cacheValue, ok := ta.revocationCache[sn]; ok {
		if time.Now().UTC().Sub(cacheValue.timestamp) < ta.cacheExpiration {
			ta.logger.Debugf("TLSAuth: using cached value for cert %s: %t", sn, cacheValue.revoked)
			return cacheValue.revoked, nil
		}

		ta.logger.Debugf("TLSAuth: cached value expired, removing from cache")
		delete(ta.revocationCache, sn)
	} else {
		ta.logger.Tracef("TLSAuth: no cached value for cert %s", sn)
	}

	revokedByOCSP, cacheOCSP := ta.isOCSPRevoked(cert, issuer)
	revokedByCRL, cacheCRL := ta.isCRLRevoked(cert)
	revoked := revokedByOCSP || revokedByCRL

	if cacheOCSP && cacheCRL {
		ta.revocationCache[sn] = cacheEntry{
			revoked:   revoked,
			timestamp: time.Now().UTC(),
		}
	}

	return revoked, nil
}

func (ta *TLSAuth) isInvalid(cert *x509.Certificate, issuer *x509.Certificate) (bool, error) {
	if ta.isExpired(cert) {
		return true, nil
	}

	revoked, err := ta.isRevoked(cert, issuer)
	if err != nil {
		// Fail securely, if we can't check the revocation status, let's consider the cert invalid
		// We may change this in the future based on users feedback, but this seems the most sensible thing to do
		return true, fmt.Errorf("could not check for client certification revocation status: %w", err)
	}

	return revoked, nil
}

func (ta *TLSAuth) setAllowedOu(allowedOus []string) error {
	uniqueOUs := make(map[string]struct{})

	for _, ou := range allowedOus {
		// disallow empty ou
		if ou == "" {
			return errors.New("empty ou isn't allowed")
		}

		if _, exists := uniqueOUs[ou]; exists {
			ta.logger.Warningf("dropping duplicate ou %s", ou)
			continue
		}

		uniqueOUs[ou] = struct{}{}

		ta.AllowedOUs = append(ta.AllowedOUs, ou)
	}

	return nil
}

func (ta *TLSAuth) ValidateCert(c *gin.Context) (bool, string, error) {
	// Checks cert validity, Returns true + CN if client cert matches requested OU
	var clientCert *x509.Certificate

	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		// do not error if it's not TLS or there are no peer certs
		return false, "", nil
	}

	if len(c.Request.TLS.VerifiedChains) > 0 {
		validOU := false
		clientCert = c.Request.TLS.VerifiedChains[0][0]

		for _, ou := range clientCert.Subject.OrganizationalUnit {
			for _, allowedOu := range ta.AllowedOUs {
				if allowedOu == ou {
					validOU = true
					break
				}
			}
		}

		if !validOU {
			return false, "", fmt.Errorf("client certificate OU (%v) doesn't match expected OU (%v)",
				clientCert.Subject.OrganizationalUnit, ta.AllowedOUs)
		}

		revoked, err := ta.isInvalid(clientCert, c.Request.TLS.VerifiedChains[0][1])
		if err != nil {
			ta.logger.Errorf("TLSAuth: error checking if client certificate is revoked: %s", err)
			return false, "", fmt.Errorf("could not check for client certification revocation status: %w", err)
		}

		if revoked {
			return false, "", fmt.Errorf("client certificate for CN=%s OU=%s is revoked", clientCert.Subject.CommonName, clientCert.Subject.OrganizationalUnit)
		}

		ta.logger.Debugf("client OU %v is allowed vs required OU %v", clientCert.Subject.OrganizationalUnit, ta.AllowedOUs)

		return true, clientCert.Subject.CommonName, nil
	}

	return false, "", errors.New("no verified cert in request")
}

func NewTLSAuth(allowedOus []string, crlPath string, cacheExpiration time.Duration, logger *log.Entry) (*TLSAuth, error) {
	ta := &TLSAuth{
		revocationCache: map[string]cacheEntry{},
		cacheExpiration: cacheExpiration,
		CrlPath:         crlPath,
		logger:          logger,
	}

	err := ta.setAllowedOu(allowedOus)
	if err != nil {
		return nil, err
	}

	return ta, nil
}
