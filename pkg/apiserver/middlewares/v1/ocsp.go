package v1

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type OCSPChecker struct {
	logger *log.Entry
}

func NewOCSPChecker(logger *log.Entry) *OCSPChecker {
	return &OCSPChecker{
		logger: logger,
	}
}

func (oc *OCSPChecker) query(ctx context.Context, server string, cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		oc.logger.Errorf("TLSAuth: error creating OCSP request: %s", err)
		return nil, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewBuffer(req))
	if err != nil {
		oc.logger.Error("TLSAuth: cannot create HTTP request for OCSP")
		return nil, err
	}

	ocspURL, err := url.Parse(server)
	if err != nil {
		oc.logger.Error("TLSAuth: cannot parse OCSP URL")
		return nil, err
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("Host", ocspURL.Host)

	httpClient := &http.Client{}

	// XXX: timeout, context?
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		oc.logger.Error("TLSAuth: cannot send HTTP request to OCSP")
		return nil, err
	}
	defer httpResponse.Body.Close()

	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		oc.logger.Error("TLSAuth: cannot read HTTP response from OCSP")
		return nil, err
	}

	ocspResponse, err := ocsp.ParseResponseForCert(output, cert, issuer)

	return ocspResponse, err
}

// isRevokedBy checks if the client certificate is revoked by the issuer via any of the OCSP servers present in the certificate.
// It returns a boolean indicating if the certificate is revoked and a boolean indicating
// if the OCSP check was successful and could be cached.
func (oc *OCSPChecker) isRevokedBy(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate) (bool, bool) {
	if len(cert.OCSPServer) == 0 {
		oc.logger.Infof("TLSAuth: no OCSP Server present in client certificate, skipping OCSP verification")
		return false, true
	}

	for _, server := range cert.OCSPServer {
		ocspResponse, err := oc.query(ctx, server, cert, issuer)
		if err != nil {
			oc.logger.Errorf("TLSAuth: error querying OCSP server %s: %s", server, err)
			continue
		}

		switch ocspResponse.Status {
		case ocsp.Good:
			return false, true
		case ocsp.Revoked:
			oc.logger.Errorf("TLSAuth: client certificate is revoked by server %s", server)
			return true, true
		case ocsp.Unknown:
			log.Debugf("unknown OCSP status for server %s", server)
			continue
		}
	}

	log.Infof("Could not get any valid OCSP response, assuming the cert is revoked")

	return true, false
}
