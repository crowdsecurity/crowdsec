package v1

import (
	"crypto/x509"
	"fmt"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func ValidateCert(c *gin.Context, AllowedOus []string) (bool, string, error) {
	//Checks cert validity, Returns true + CN if client cert matches requested OU
	var clientCert *x509.Certificate
	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		//do not error if it's not TLS or there are no peer certs
		return false, "", nil
	}

	if len(c.Request.TLS.VerifiedChains) > 0 {
		validOU := false
		clientCert = c.Request.TLS.VerifiedChains[0][0]
		for _, ou := range clientCert.Subject.OrganizationalUnit {
			for _, allowedOu := range AllowedOus {
				if allowedOu == ou {
					validOU = true
					break
				}
			}
		}
		if !validOU {
			//log.Errorf("Cert Authentication: client certificate OU isn't valid")
			return false, "", fmt.Errorf("client certificate OU (%v) doesn't match expected OU (%v)",
				clientCert.Subject.OrganizationalUnit, AllowedOus)
		}
		log.Infof("client OU %v is allowed vs required OU %v", clientCert.Subject.OrganizationalUnit, AllowedOus)
		return true, clientCert.Subject.CommonName, nil
	}
	return false, "", fmt.Errorf("no verified cert in request")
}
