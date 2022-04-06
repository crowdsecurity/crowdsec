package v1

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func ocspQuery(server string, cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		log.Errorf("TLSAuth: error creating OCSP request: %s", err)
		return nil, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, server, bytes.NewBuffer(req))
	if err != nil {
		log.Error("TLSAuth: cannot create HTTP request for OCSP")
		return nil, err
	}
	ocspURL, err := url.Parse(server)
	if err != nil {
		log.Error("TLSAuth: cannot parse OCSP URL")
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		log.Error("TLSAuth: cannot send HTTP request to OCSP")
		return nil, err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Error("TLSAuth: cannot read HTTP response from OCSP")
		return nil, err
	}
	ocspResponse, err := ocsp.ParseResponseForCert(output, cert, issuer)
	return ocspResponse, err
}

func isExpired(cert *x509.Certificate) bool {
	now := time.Now().UTC()

	if cert.NotAfter.UTC().Before(now) {
		log.Errorf("TLSAuth: client certificate is expired (NotAfter: %s)", cert.NotAfter.UTC())
		return true
	}
	if cert.NotBefore.UTC().After(now) {
		log.Errorf("TLSAuth: client certificate is not yet valid (NotBefore: %s)", cert.NotBefore.UTC())
		return true
	}
	return false
}

func isOCSPRevoked(cert *x509.Certificate, issuer *x509.Certificate) (bool, error) {
	if cert.OCSPServer == nil || (cert.OCSPServer != nil && len(cert.OCSPServer) == 0) {
		log.Infof("TLSAuth: no OCSP Server present in client certificate, skipping OCSP verification")
		return false, nil
	}
	for _, server := range cert.OCSPServer {
		ocspResponse, err := ocspQuery(server, cert, issuer)
		if err != nil {
			log.Errorf("TLSAuth: error querying OCSP server %s: %s", server, err)
			continue
		}
		switch ocspResponse.Status {
		case ocsp.Good:
			return false, nil
		case ocsp.Revoked:
			return true, fmt.Errorf("client certificate is revoked by server %s", server)
		case ocsp.Unknown:
			log.Debugf("unknow OCSP status for server %s", server)
			continue
		}
	}
	log.Infof("Could not get any valid OCSP response, assuming the cert is revoked")
	return true, nil
}

func isRevoked(cert *x509.Certificate, issuer *x509.Certificate) (bool, error) {
	revoked, err := isOCSPRevoked(cert, issuer)
	if err != nil {
		return true, err
	}
	if revoked {
		return revoked, nil
	}
	return false, nil
}

func isInvalid(cert *x509.Certificate, issuer *x509.Certificate) (bool, error) {
	if isExpired(cert) {
		return true, nil
	}
	revoked, err := isRevoked(cert, issuer)
	if err != nil {
		//Fail securely, if we can't check the revokation status, let's consider the cert invalid
		//We may change this in the future based on users feedback, but this seems the most sensible thing to do
		return true, errors.Wrap(err, "could not check for client certification revokation status")
	}

	return revoked, nil
}

func ValidateCert(c *gin.Context, AllowedOu []string) (bool, string, error) {
	//Checks cert validity, Returns true + CN if client cert matches requested OU

	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		//do not error if it's not TLS or there are no peer certs
		return false, "", nil
	}

	if len(c.Request.TLS.VerifiedChains) > 0 {
		validOU := false
		clientCert := c.Request.TLS.VerifiedChains[0][0]
		if len(c.Request.TLS.VerifiedChains[0]) == 1 {
			log.Errorf("TLSAuth: no issuer cert in chain")
			return false, "", errors.New("no issuer cert in chain")
		}
		for _, ou := range clientCert.Subject.OrganizationalUnit {
			for _, allowedOu := range AllowedOu {
				if allowedOu == ou {
					validOU = true
					break
				}
			}
		}
		if !validOU {
			log.Errorf("TLSAuth: client certificate is not from a bouncer")
			return false, "", fmt.Errorf("client certificate OU (%+v) doesn't match expected OU", clientCert.Subject.OrganizationalUnit)
		}
		revoked, err := isInvalid(clientCert, c.Request.TLS.VerifiedChains[0][1])
		if err != nil {
			log.Errorf("TLSAuth: error checking if client certificate is revoked: %s", err)
			return false, "", errors.Wrap(err, "could not check for client certification revokation status")
		}
		if revoked {
			return false, "", fmt.Errorf("client certificate is revoked")
		}
		return true, clientCert.Subject.CommonName, nil
	}
	return false, "", fmt.Errorf("no verified cert in request")
}
