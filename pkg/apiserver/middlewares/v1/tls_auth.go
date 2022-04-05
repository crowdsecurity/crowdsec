package v1

import (
	"fmt"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type TLSAuth struct {
	AllowedOU string
}

func (t *TLSAuth) ValidateCert(c *gin.Context) (bool, string) {
	if c.Request.TLS != nil {
		if len(c.Request.TLS.VerifiedChains) > 0 {
			validOU := false
			clientCert := c.Request.TLS.VerifiedChains[0][0]
			for _, ou := range clientCert.Subject.OrganizationalUnit {
				if t.AllowedOU == ou {
					validOU = true
				}
			}
			if !validOU {
				log.Errorf("APIKey: client certificate is not from a bouncer")
				return false, ""
			}
			return true, fmt.Sprintf("%s-%s", clientCert.Subject.CommonName, c.ClientIP())
		} else {
			log.Error("Found no verified certs in request")
			return false, ""
		}
	}
	return false, ""
}
