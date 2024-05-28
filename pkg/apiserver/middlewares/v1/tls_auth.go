package v1

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type TLSAuth struct {
	AllowedOUs      []string
	crlChecker      *CRLChecker
	ocspChecker     *OCSPChecker
	revocationCache *RevocationCache
	logger          *log.Entry
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

// checkRevocationPath checks a single chain against OCSP and CRL
func (ta *TLSAuth) checkRevocationPath(chain []*x509.Certificate) bool {
	for i := len(chain) - 1; i > 0; i-- {
		cert := chain[i-1]
		issuer := chain[i]

		if revoked, cached := ta.revocationCache.Get(cert, issuer, ta.logger); cached {
			return revoked
		}

		revokedByOCSP, checkedByOCSP := ta.ocspChecker.isRevokedBy(cert, issuer)
		revokedByCRL, checkedByCRL := ta.crlChecker.isRevokedBy(cert, issuer)
		revoked := revokedByOCSP || revokedByCRL

		if checkedByOCSP && checkedByCRL {
			ta.revocationCache.Set(cert, issuer, revoked)
		}

		if revoked {
			return true
		}
	}

	return false
}

func (ta *TLSAuth) setAllowedOu(allowedOus []string) error {
	uniqueOUs := make(map[string]struct{})

	for _, ou := range allowedOus {
		// disallow empty ou
		if ou == "" {
			return errors.New("allowed_ou configuration contains invalid empty string")
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

func (ta *TLSAuth) checkAllowedOU(cert *x509.Certificate) bool {
	for _, ou := range cert.Subject.OrganizationalUnit {
		for _, allowedOu := range ta.AllowedOUs {
			if allowedOu == ou {
				return true
			}
		}
	}

	return false
}

func (ta *TLSAuth) ValidateCert(c *gin.Context) (bool, string, error) {
	// Checks cert validity, Returns true + CN if client cert matches requested OU
	var leaf *x509.Certificate

	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		// do not error if it's not TLS or there are no peer certs
		return false, "", nil
	}

	if len(c.Request.TLS.VerifiedChains) == 0 {
		return false, "", errors.New("no verified cert in request")
	}

	// although there can be multiple chains, the leaf certificate is the same
	// we take the first one
	leaf = c.Request.TLS.VerifiedChains[0][0]

	if !ta.checkAllowedOU(leaf) {
		return false, "", fmt.Errorf("client certificate OU (%v) doesn't match expected OU (%v)",
			leaf.Subject.OrganizationalUnit, ta.AllowedOUs)
	}

	if ta.isExpired(leaf) {
		return false, "", nil
	}

	for _, chain := range c.Request.TLS.VerifiedChains {
		if ta.checkRevocationPath(chain) {
			// TODO: we might bubble up the issuer information here? store in cache too?
			return false, "", fmt.Errorf("client certificate for CN=%s OU=%s is revoked",
				leaf.Subject.CommonName, leaf.Subject.OrganizationalUnit)
		}
	}

	return true, leaf.Subject.CommonName, nil
}

func NewTLSAuth(allowedOus []string, crlPath string, cacheExpiration time.Duration, logger *log.Entry) (*TLSAuth, error) {
	var err error

	ta := &TLSAuth{
		revocationCache: NewRevocationCache(cacheExpiration),
		ocspChecker:     NewOCSPChecker(logger),
		logger:          logger,
	}

	switch crlPath {
	case "":
		logger.Info("no crl_path, skipping CRL checks")
	default:
		ta.crlChecker, err = NewCRLChecker(crlPath, logger)
		if err != nil {
			return nil, err
		}
	}

	if err := ta.setAllowedOu(allowedOus); err != nil {
		return nil, err
	}

	return ta, nil
}
