package v1

import (
	"fmt"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func ValidateCert(c *gin.Context, AllowedOu []string) (bool, string, error) {
	//Checks cert validity, Returns true + CN if client cert matches requested OU

	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		//do not error if it's not TLS or there are no peer certs
		return false, "", nil
	}

	if len(c.Request.TLS.VerifiedChains) > 0 {
		validOU := false
		clientCert := c.Request.TLS.VerifiedChains[0][0]
		for _, ou := range clientCert.Subject.OrganizationalUnit {
			for _, allowedOu := range AllowedOu {
				if allowedOu == ou {
					validOU = true
					break
				}
			}
		}
		if !validOU {
			log.Errorf("APIKey: client certificate is not from a bouncer")
			return false, "", fmt.Errorf("client certificate OU (%+v) doesn't match expected OU", clientCert.Subject.OrganizationalUnit)
		}
		return true, clientCert.Subject.CommonName, nil
	}
	return false, "", fmt.Errorf("no verified cert in request")
}
