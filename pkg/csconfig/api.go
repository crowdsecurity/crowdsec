package csconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/yamlpatch"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type APICfg struct {
	Client *LocalApiClientCfg `yaml:"client"`
	Server *LocalApiServerCfg `yaml:"server"`
	CTI    *CTICfg            `yaml:"cti"`
}

type ApiCredentialsCfg struct {
	URL        string `yaml:"url,omitempty" json:"url,omitempty"`
	Login      string `yaml:"login,omitempty" json:"login,omitempty"`
	Password   string `yaml:"password,omitempty" json:"-"`
	CACertPath string `yaml:"ca_cert_path,omitempty"`
	KeyPath    string `yaml:"key_path,omitempty"`
	CertPath   string `yaml:"cert_path,omitempty"`
}

/*global api config (for lapi->oapi)*/
type OnlineApiClientCfg struct {
	CredentialsFilePath string             `yaml:"credentials_path,omitempty"` //credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsCfg `yaml:"-"`
}

/*local api config (for crowdsec/cscli->lapi)*/
type LocalApiClientCfg struct {
	CredentialsFilePath string             `yaml:"credentials_path,omitempty"` //credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsCfg `yaml:"-"`
	InsecureSkipVerify  *bool              `yaml:"insecure_skip_verify"` // check if api certificate is bad or not
}

type CTICfg struct {
	Key          *string        `yaml:"key,omitempty"`
	CacheTimeout *time.Duration `yaml:"cache_timeout,omitempty"`
	CacheSize    *int           `yaml:"cache_size,omitempty"`
	Enabled      bool           `yaml:"-"`
}

func (a *CTICfg) Load() error { //XX
	log.Warningf("CTICfg init, key = %p", a.Key)
	if a.Key == nil {
		a.Enabled = false
	}
	if a.Key != nil && *a.Key == "" {
		return fmt.Errorf("empty cti key")
	}
	if a.CacheTimeout == nil {
		a.CacheTimeout = new(time.Duration)
		*a.CacheTimeout = 10 * time.Minute
	}
	if a.CacheSize == nil {
		a.CacheSize = new(int)
		*a.CacheSize = 100
	}
	a.Enabled = true
	return nil
}

func (o *OnlineApiClientCfg) Load() error {
	o.Credentials = new(ApiCredentialsCfg)
	fcontent, err := os.ReadFile(o.CredentialsFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to read api server credentials configuration file '%s'", o.CredentialsFilePath)
	}
	err = yaml.UnmarshalStrict(fcontent, o.Credentials)
	if err != nil {
		return errors.Wrapf(err, "failed unmarshaling api server credentials configuration file '%s'", o.CredentialsFilePath)
	}
	if o.Credentials.Login == "" || o.Credentials.Password == "" || o.Credentials.URL == "" {
		log.Warningf("can't load CAPI credentials from '%s' (missing field)", o.CredentialsFilePath)
		o.Credentials = nil
	}
	return nil
}

func (l *LocalApiClientCfg) Load() error {
	patcher := yamlpatch.NewPatcher(l.CredentialsFilePath, ".local")
	fcontent, err := patcher.MergedPatchContent()
	if err != nil {
		return err
	}
	err = yaml.UnmarshalStrict(fcontent, &l.Credentials)
	if err != nil {
		return errors.Wrapf(err, "failed unmarshaling api client credential configuration file '%s'", l.CredentialsFilePath)
	}
	if l.Credentials == nil || l.Credentials.URL == "" {
		return fmt.Errorf("no credentials or URL found in api client configuration '%s'", l.CredentialsFilePath)
	}

	if l.Credentials != nil && l.Credentials.URL != "" {
		if !strings.HasSuffix(l.Credentials.URL, "/") {
			l.Credentials.URL = l.Credentials.URL + "/"
		}
	}

	if l.Credentials.Login != "" && (l.Credentials.CACertPath != "" || l.Credentials.CertPath != "" || l.Credentials.KeyPath != "") {
		return fmt.Errorf("user/password authentication and TLS authentication are mutually exclusive")
	}

	if l.InsecureSkipVerify == nil {
		apiclient.InsecureSkipVerify = false
	} else {
		apiclient.InsecureSkipVerify = *l.InsecureSkipVerify
	}

	if l.Credentials.CACertPath != "" && l.Credentials.CertPath != "" && l.Credentials.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(l.Credentials.CertPath, l.Credentials.KeyPath)
		if err != nil {
			return errors.Wrapf(err, "failed to load api client certificate")
		}

		caCert, err := os.ReadFile(l.Credentials.CACertPath)
		if err != nil {
			return errors.Wrapf(err, "failed to load cacert")
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		apiclient.Cert = &cert
		apiclient.CaCertPool = caCertPool
	}
	return nil
}

func (lapiCfg *LocalApiServerCfg) GetTrustedIPs() ([]net.IPNet, error) {
	trustedIPs := make([]net.IPNet, 0)
	for _, ip := range lapiCfg.TrustedIPs {
		cidr := toValidCIDR(ip)
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		trustedIPs = append(trustedIPs, *ipNet)
	}
	return trustedIPs, nil
}

func toValidCIDR(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}

	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

/*local api service configuration*/
type LocalApiServerCfg struct {
	Enable                 *bool               `yaml:"enable"`
	ListenURI              string              `yaml:"listen_uri,omitempty"` //127.0.0.1:8080
	TLS                    *TLSCfg             `yaml:"tls"`
	DbConfig               *DatabaseCfg        `yaml:"-"`
	LogDir                 string              `yaml:"-"`
	LogMedia               string              `yaml:"-"`
	OnlineClient           *OnlineApiClientCfg `yaml:"online_client"`
	ProfilesPath           string              `yaml:"profiles_path,omitempty"`
	ConsoleConfigPath      string              `yaml:"console_path,omitempty"`
	ConsoleConfig          *ConsoleConfig      `yaml:"-"`
	Profiles               []*ProfileCfg       `yaml:"-"`
	LogLevel               *log.Level          `yaml:"log_level"`
	UseForwardedForHeaders bool                `yaml:"use_forwarded_for_headers,omitempty"`
	TrustedProxies         *[]string           `yaml:"trusted_proxies,omitempty"`
	CompressLogs           *bool               `yaml:"-"`
	LogMaxSize             int                 `yaml:"-"`
	LogMaxAge              int                 `yaml:"-"`
	LogMaxFiles            int                 `yaml:"-"`
	TrustedIPs             []string            `yaml:"trusted_ips,omitempty"`
}

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

func (c *Config) LoadAPIServer() error {

	if c.DisableAPI {
		log.Warning("crowdsec local API is disabled from flag")
	}

	if c.API.Server == nil {
		log.Warning("crowdsec local API is disabled because its configuration is not present")
		c.DisableAPI = true
		return nil
	}

	if c.API.Server.Enable == nil {
		// if the option is not present, it is enabled by default
		c.API.Server.Enable = types.BoolPtr(true)
	}

	if !*c.API.Server.Enable {
		log.Warning("crowdsec local API is disabled because 'enable' is set to false")
		c.DisableAPI = true
		return nil
	}

	if c.DisableAPI {
		return nil
	}

	if err := c.LoadCommon(); err != nil {
		return fmt.Errorf("loading common configuration: %s", err)
	}
	c.API.Server.LogDir = c.Common.LogDir
	c.API.Server.LogMedia = c.Common.LogMedia
	c.API.Server.CompressLogs = c.Common.CompressLogs
	c.API.Server.LogMaxSize = c.Common.LogMaxSize
	c.API.Server.LogMaxAge = c.Common.LogMaxAge
	c.API.Server.LogMaxFiles = c.Common.LogMaxFiles
	if c.API.Server.UseForwardedForHeaders && c.API.Server.TrustedProxies == nil {
		c.API.Server.TrustedProxies = &[]string{"0.0.0.0/0"}
	}
	if c.API.Server.TrustedProxies != nil {
		c.API.Server.UseForwardedForHeaders = true
	}
	if err := c.API.Server.LoadProfiles(); err != nil {
		return errors.Wrap(err, "while loading profiles for LAPI")
	}
	if c.API.Server.ConsoleConfigPath == "" {
		c.API.Server.ConsoleConfigPath = DefaultConsoleConfigFilePath
	}
	if err := c.API.Server.LoadConsoleConfig(); err != nil {
		return errors.Wrap(err, "while loading console options")
	}

	if c.API.Server.OnlineClient != nil && c.API.Server.OnlineClient.CredentialsFilePath != "" {
		if err := c.API.Server.OnlineClient.Load(); err != nil {
			return errors.Wrap(err, "loading online client credentials")
		}
	}
	if c.API.Server.OnlineClient == nil || c.API.Server.OnlineClient.Credentials == nil {
		log.Printf("push and pull to Central API disabled")
	}

	log.Printf("Config load, c.API.CTI : %p", c.API.CTI)
	if c.API.CTI != nil {
		if err := c.API.CTI.Load(); err != nil {
			return errors.Wrap(err, "loading CTI configuration")
		}
	}

	if err := c.LoadDBConfig(); err != nil {
		return err
	}

	return nil
}

func (c *Config) LoadAPIClient() error {
	if c.API == nil || c.API.Client == nil || c.API.Client.CredentialsFilePath == "" || c.DisableAgent {
		return fmt.Errorf("no API client section in configuration")
	}

	if err := c.API.Client.Load(); err != nil {
		return err
	}

	return nil
}
