package csconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

type TLSCfg struct {
	CertFilePath       string         `yaml:"cert_file"`
	KeyFilePath        string         `yaml:"key_file"`
	ClientVerification string         `yaml:"client_verification,omitempty"`
	ServerName         string         `yaml:"server_name"`
	CACertPath         string         `yaml:"ca_cert_path"`
	AllowedAgentsOU    []string       `yaml:"agents_allowed_ou"`
	AllowedBouncersOU  []string       `yaml:"bouncers_allowed_ou"`
	CRLPath            string         `yaml:"crl_path"`
	CacheExpiration    *time.Duration `yaml:"cache_expiration,omitempty"`
}

func (t *TLSCfg) GetAuthType() (tls.ClientAuthType, error) {
	if t.ClientVerification == "" {
		// sounds like a sane default: verify client cert if given, but don't make it mandatory
		return tls.VerifyClientCertIfGiven, nil
	}

	switch t.ClientVerification {
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
		return 0, fmt.Errorf("unknown TLS client_verification value: %s", t.ClientVerification)
	}
}

func (t *TLSCfg) GetTLSConfig() (*tls.Config, error) {
	if t == nil {
		return &tls.Config{}, nil
	}

	clientAuthType, err := t.GetAuthType()
	if err != nil {
		return nil, err
	}

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Warnf("Error loading system CA certificates: %s", err)
	}

	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}

	// the > condition below is a weird way to say "if a client certificate is required"
	// see https://pkg.go.dev/crypto/tls#ClientAuthType
	if clientAuthType > tls.RequestClientCert && t.CACertPath != "" {
		log.Infof("(tls) Client Auth Type set to %s", clientAuthType.String())

		caCert, err := os.ReadFile(t.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("while opening cert file: %w", err)
		}

		caCertPool.AppendCertsFromPEM(caCert)
	}

	return &tls.Config{
		ServerName: t.ServerName, //should it be removed ?
		ClientAuth: clientAuthType,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12, // TLS versions below 1.2 are considered insecure - see https://www.rfc-editor.org/rfc/rfc7525.txt for details
	}, nil
}
