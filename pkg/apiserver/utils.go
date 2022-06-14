package apiserver

import (
	"crypto/tls"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func getTLSAuthType(authType string) (tls.ClientAuthType, error) {
	switch authType {
	case "NoClientCert":
		return tls.NoClientCert, nil
	case "RequestClientCert":
		log.Warn("RequestClientCert is insecure, please use VerifyClientCertIfGiven or RequireAndVerifyClientCert instead")
		return tls.RequestClientCert, nil
	case "RequireAnyClientCert":
		log.Warn("RequireAnyClientCert is insecure, please use VerifyClientCertIfGiven or RequireAndVerifyClientCert instead")
		return tls.RequireAnyClientCert, nil
	case "VerifyClientCertIfGiven":
		return tls.VerifyClientCertIfGiven, nil
	case "RequireAndVerifyClientCert":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return 0, fmt.Errorf("unknown TLS client_verification value: %s", authType)
	}
}
