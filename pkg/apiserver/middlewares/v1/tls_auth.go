package v1

import (
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type TLSAuth struct {
}

func (t *TLSAuth) ValidateCert(c *gin.Context, prefix string) bool {
	if c.Request.TLS != nil {
		if len(c.Request.TLS.VerifiedChains) > 0 {
			clientCert := c.Request.TLS.VerifiedChains[0][0]
			if !strings.HasPrefix(clientCert.Subject.CommonName, prefix) {
				log.Errorf("APIKey: client certificate is not from a bouncer : %s", clientCert.Subject.CommonName)
				return false
			} else {
				return true
			}
		} else {
			log.Error("Found no verified certs in request")
			return false
		}
	}
	return false
}
