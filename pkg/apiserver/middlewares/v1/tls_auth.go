package v1

import (
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
func (ta *TLSAuth) checkRevocationPath(chain []*x509.Certificate) (bool, bool) {
	couldCheck := true
	revoked := false

	// starting from the root CA and moving towards the leaf certificate,
	// check for revocation of intermediates too
	for i := len(chain) - 1; i > 0; i-- {
		cert := chain[i-1]
		issuer := chain[i]

		revokedByOCSP, checkedByOCSP := ta.ocspChecker.isRevokedBy(cert, issuer)
		revokedByCRL, checkedByCRL := ta.crlChecker.isRevokedBy(cert, issuer)

		// if we ever fail to check OCSP or CRL, we should not cache the result
		couldCheck = couldCheck && checkedByOCSP && checkedByCRL

		// if we confirmed a revocation (or a failure to check) return immediately
		revoked = revoked || revokedByOCSP || revokedByCRL
		if revoked {
			break
		}
	}

	return revoked, couldCheck
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

	if err := ta.checkAllowedOU(leaf.Subject.OrganizationalUnit); err != nil {
		ta.logger.Errorf("TLSAuth: %s", err)
		return false, "", err
	}

	if ta.isExpired(leaf) {
		return false, "", nil
	}

	if revoked, cached := ta.revocationCache.Get(leaf); cached {
		return revoked, leaf.Subject.CommonName, nil
	}

	okToCache := true

	revoked := false

	var couldCheck bool

	for _, chain := range c.Request.TLS.VerifiedChains {
		revoked, couldCheck = ta.checkRevocationPath(chain)
		okToCache = okToCache && couldCheck
		if revoked {
			break
		}
	}

	if okToCache {
		ta.revocationCache.Set(leaf, revoked)
	}

	if revoked {
		// XXX: could we bubble up the reason?
		return false, "", fmt.Errorf("client certificate for CN=%s OU=%s is revoked",
			leaf.Subject.CommonName, leaf.Subject.OrganizationalUnit)
	}

	return true, leaf.Subject.CommonName, nil
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
