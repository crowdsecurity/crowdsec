package v1

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
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
func (ta *TLSAuth) checkRevocationPath(ctx context.Context, chain []*x509.Certificate) (error, bool) { //nolint:revive
	// if we ever fail to check OCSP or CRL, we should not cache the result
	couldCheck := true

	// starting from the root CA and moving towards the leaf certificate,
	// check for revocation of intermediates too
	for i := len(chain) - 1; i > 0; i-- {
		cert := chain[i-1]
		issuer := chain[i]

		revokedByOCSP, checkedByOCSP := ta.ocspChecker.isRevokedBy(ctx, cert, issuer)
		couldCheck = couldCheck && checkedByOCSP

		if revokedByOCSP && checkedByOCSP {
			return errors.New("certificate revoked by OCSP"), couldCheck
		}

		revokedByCRL, checkedByCRL := ta.crlChecker.isRevokedBy(cert, issuer)
		couldCheck = couldCheck && checkedByCRL

		if revokedByCRL && checkedByCRL {
			return errors.New("certificate revoked by CRL"), couldCheck
		}
	}

	return nil, couldCheck
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

func (ta *TLSAuth) checkAllowedOU(ous []string) error {
	for _, ou := range ous {
		if slices.Contains(ta.AllowedOUs, ou) {
			return nil
		}
	}

	return fmt.Errorf("client certificate OU %v doesn't match expected OU %v", ous, ta.AllowedOUs)
}

func (ta *TLSAuth) ValidateCert(c *gin.Context) (string, error) {
	// Checks cert validity, Returns true + CN if client cert matches requested OU
	var leaf *x509.Certificate

	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		return "", errors.New("no certificate in request")
	}

	if len(c.Request.TLS.VerifiedChains) == 0 {
		return "", errors.New("no verified cert in request")
	}

	// although there can be multiple chains, the leaf certificate is the same
	// we take the first one
	leaf = c.Request.TLS.VerifiedChains[0][0]

	if err := ta.checkAllowedOU(leaf.Subject.OrganizationalUnit); err != nil {
		return "", err
	}

	if ta.isExpired(leaf) {
		return "", errors.New("client certificate is expired")
	}

	if validErr, cached := ta.revocationCache.Get(leaf); cached {
		if validErr != nil {
			return "", fmt.Errorf("(cache) %w", validErr)
		}

		return leaf.Subject.CommonName, nil
	}

	okToCache := true

	var (
		validErr   error
		couldCheck bool
	)

	for _, chain := range c.Request.TLS.VerifiedChains {
		validErr, couldCheck = ta.checkRevocationPath(c.Request.Context(), chain)
		okToCache = okToCache && couldCheck

		if validErr != nil {
			break
		}
	}

	if okToCache {
		ta.revocationCache.Set(leaf, validErr)
	}

	if validErr != nil {
		return "", validErr
	}

	return leaf.Subject.CommonName, nil
}

func NewTLSAuth(allowedOus []string, crlPath string, cacheExpiration time.Duration, logger *log.Entry) (*TLSAuth, error) {
	var err error

	cache := NewRevocationCache(cacheExpiration, logger)

	ta := &TLSAuth{
		revocationCache: cache,
		ocspChecker:     NewOCSPChecker(logger),
		logger:          logger,
	}

	switch crlPath {
	case "":
		logger.Info("no crl_path, skipping CRL checks")
	default:
		ta.crlChecker, err = NewCRLChecker(crlPath, cache.Empty, logger)
		if err != nil {
			return nil, err
		}
	}

	if err := ta.setAllowedOu(allowedOus); err != nil {
		return nil, err
	}

	return ta, nil
}
