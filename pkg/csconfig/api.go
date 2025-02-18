package csconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/yamlpatch"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

type APICfg struct {
	Client *LocalApiClientCfg `yaml:"client"`
	Server *LocalApiServerCfg `yaml:"server"`
	CTI    *CTICfg            `yaml:"cti"`
}

type ApiCredentialsCfg struct {
	PapiURL    string `yaml:"papi_url,omitempty" json:"papi_url,omitempty"`
	URL        string `yaml:"url,omitempty" json:"url,omitempty"`
	Login      string `yaml:"login,omitempty" json:"login,omitempty"`
	Password   string `yaml:"password,omitempty" json:"-"`
	CACertPath string `yaml:"ca_cert_path,omitempty"`
	KeyPath    string `yaml:"key_path,omitempty"`
	CertPath   string `yaml:"cert_path,omitempty"`
}

type CapiPullConfig struct {
	Community  *bool `yaml:"community,omitempty"`
	Blocklists *bool `yaml:"blocklists,omitempty"`
}

/*global api config (for lapi->capi)*/
type OnlineApiClientCfg struct {
	CredentialsFilePath string             `yaml:"credentials_path,omitempty"` // credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsCfg `yaml:"-"`
	PullConfig          CapiPullConfig     `yaml:"pull,omitempty"`
	Sharing             *bool              `yaml:"sharing,omitempty"`
}

/*local api config (for crowdsec/cscli->lapi)*/
type LocalApiClientCfg struct {
	CredentialsFilePath string             `yaml:"credentials_path,omitempty"` // credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsCfg `yaml:"-"`
	InsecureSkipVerify  *bool              `yaml:"insecure_skip_verify"` // check if api certificate is bad or not
}

type CTICfg struct {
	Key          *string        `yaml:"key,omitempty"`
	CacheTimeout *time.Duration `yaml:"cache_timeout,omitempty"`
	CacheSize    *int           `yaml:"cache_size,omitempty"`
	Enabled      *bool          `yaml:"enabled,omitempty"`
	LogLevel     *log.Level     `yaml:"log_level,omitempty"`
}

func (a *CTICfg) Load() error {
	if a.Key == nil {
		a.Enabled = ptr.Of(false)
	}

	if a.Key != nil && *a.Key == "" {
		return errors.New("empty cti key")
	}

	if a.Enabled == nil {
		a.Enabled = ptr.Of(true)
	}

	if a.CacheTimeout == nil {
		a.CacheTimeout = new(time.Duration)
		*a.CacheTimeout = 10 * time.Minute
	}

	if a.CacheSize == nil {
		a.CacheSize = new(int)
		*a.CacheSize = 100
	}

	return nil
}

func (o *OnlineApiClientCfg) Load() error {
	o.Credentials = new(ApiCredentialsCfg)

	fcontent, err := os.ReadFile(o.CredentialsFilePath)
	if err != nil {
		return err
	}

	dec := yaml.NewDecoder(bytes.NewReader(fcontent))
	dec.KnownFields(true)

	err = dec.Decode(o.Credentials)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to parse api server credentials configuration file '%s': %w", o.CredentialsFilePath, err)
		}
	}

	switch {
	case o.Credentials.Login == "":
		log.Warningf("can't load CAPI credentials from '%s' (missing login field)", o.CredentialsFilePath)
		o.Credentials = nil
	case o.Credentials.Password == "":
		log.Warningf("can't load CAPI credentials from '%s' (missing password field)", o.CredentialsFilePath)
		o.Credentials = nil
	case o.Credentials.URL == "":
		log.Warningf("can't load CAPI credentials from '%s' (missing url field)", o.CredentialsFilePath)
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

	configData := csstring.StrictExpand(string(fcontent), os.LookupEnv)

	dec := yaml.NewDecoder(strings.NewReader(configData))
	dec.KnownFields(true)

	err = dec.Decode(&l.Credentials)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to parse api client credential configuration file '%s': %w", l.CredentialsFilePath, err)
		}
	}

	if l.Credentials == nil || l.Credentials.URL == "" {
		return fmt.Errorf("no credentials or URL found in api client configuration '%s'", l.CredentialsFilePath)
	}

	if l.Credentials != nil && l.Credentials.URL != "" {
		// don't append a trailing slash if the URL is a unix socket
		if strings.HasPrefix(l.Credentials.URL, "http") && !strings.HasSuffix(l.Credentials.URL, "/") {
			l.Credentials.URL += "/"
		}
	}

	// is the configuration asking for client authentication via TLS?
	credTLSClientAuth := l.Credentials.CertPath != "" || l.Credentials.KeyPath != ""

	// is the configuration asking for TLS encryption and server authentication?
	credTLS := credTLSClientAuth || l.Credentials.CACertPath != ""

	credSocket := strings.HasPrefix(l.Credentials.URL, "/")

	if credTLS && credSocket {
		return errors.New("cannot use TLS with a unix socket")
	}

	if credTLSClientAuth && l.Credentials.Login != "" {
		return errors.New("user/password authentication and TLS authentication are mutually exclusive")
	}

	if l.InsecureSkipVerify == nil {
		apiclient.InsecureSkipVerify = false
	} else {
		apiclient.InsecureSkipVerify = *l.InsecureSkipVerify
	}

	if l.Credentials.CACertPath != "" {
		caCert, err := os.ReadFile(l.Credentials.CACertPath)
		if err != nil {
			return fmt.Errorf("failed to load cacert: %w", err)
		}

		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			log.Warningf("Error loading system CA certificates: %s", err)
		}

		if caCertPool == nil {
			caCertPool = x509.NewCertPool()
		}

		caCertPool.AppendCertsFromPEM(caCert)
		apiclient.CaCertPool = caCertPool
	}

	if l.Credentials.CertPath != "" && l.Credentials.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(l.Credentials.CertPath, l.Credentials.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to load api client certificate: %w", err)
		}

		apiclient.Cert = &cert
	}

	return nil
}

/*local api service configuration*/
type LocalApiServerCfg struct {
	Enable                        *bool                    `yaml:"enable"`
	ListenURI                     string                   `yaml:"listen_uri,omitempty"` // 127.0.0.1:8080
	ListenSocket                  string                   `yaml:"listen_socket,omitempty"`
	TLS                           *TLSCfg                  `yaml:"tls"`
	DbConfig                      *DatabaseCfg             `yaml:"-"`
	LogDir                        string                   `yaml:"-"`
	LogMedia                      string                   `yaml:"-"`
	OnlineClient                  *OnlineApiClientCfg      `yaml:"online_client"`
	ProfilesPath                  string                   `yaml:"profiles_path,omitempty"`
	ConsoleConfigPath             string                   `yaml:"console_path,omitempty"`
	ConsoleConfig                 *ConsoleConfig           `yaml:"-"`
	Profiles                      []*ProfileCfg            `yaml:"-"`
	LogLevel                      *log.Level               `yaml:"log_level"`
	UseForwardedForHeaders        bool                     `yaml:"use_forwarded_for_headers,omitempty"`
	TrustedProxies                *[]string                `yaml:"trusted_proxies,omitempty"`
	CompressLogs                  *bool                    `yaml:"-"`
	LogMaxSize                    int                      `yaml:"-"`
	LogMaxAge                     int                      `yaml:"-"`
	LogMaxFiles                   int                      `yaml:"-"`
	LogFormat                     string                   `yaml:"-"`
	TrustedIPs                    []string                 `yaml:"trusted_ips,omitempty"`
	PapiLogLevel                  *log.Level               `yaml:"papi_log_level"`
	DisableRemoteLapiRegistration bool                     `yaml:"disable_remote_lapi_registration,omitempty"`
	CapiWhitelistsPath            string                   `yaml:"capi_whitelists_path,omitempty"`
	CapiWhitelists                *CapiWhitelist           `yaml:"-"`
	AutoRegister                  *LocalAPIAutoRegisterCfg `yaml:"auto_registration,omitempty"`
}

func (c *LocalApiServerCfg) GetTrustedIPs() ([]net.IPNet, error) {
	trustedIPs := make([]net.IPNet, 0)

	for _, ip := range c.TrustedIPs {
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

type CapiWhitelist struct {
	Ips   []net.IP     `yaml:"ips,omitempty"`
	Cidrs []*net.IPNet `yaml:"cidrs,omitempty"`
}

type LocalAPIAutoRegisterCfg struct {
	Enable              *bool        `yaml:"enabled"`
	Token               string       `yaml:"token"`
	AllowedRanges       []string     `yaml:"allowed_ranges,omitempty"`
	AllowedRangesParsed []*net.IPNet `yaml:"-"`
}

func (c *LocalApiServerCfg) ClientURL() string {
	if c == nil {
		return ""
	}

	if c.ListenSocket != "" {
		return c.ListenSocket
	}

	if c.ListenURI != "" {
		return "http://" + c.ListenURI
	}

	return ""
}

func (c *Config) LoadAPIServer(inCli bool) error {
	if c.DisableAPI {
		log.Warning("crowdsec local API is disabled from flag")
	}

	if c.API.Server == nil {
		log.Warning("crowdsec local API is disabled")

		c.DisableAPI = true

		return nil
	}

	if c.API.Server.Enable == nil {
		// if the option is not present, it is enabled by default
		c.API.Server.Enable = ptr.Of(true)
	}

	if !*c.API.Server.Enable {
		log.Warning("crowdsec local API is disabled because 'enable' is set to false")

		c.DisableAPI = true
	}

	if c.DisableAPI {
		return nil
	}

	if c.API.Server.ListenURI == "" && c.API.Server.ListenSocket == "" {
		return errors.New("no listen_uri or listen_socket specified")
	}

	// inherit log level from common, then api->server
	var logLevel log.Level
	if c.API.Server.LogLevel != nil {
		logLevel = *c.API.Server.LogLevel
	} else if c.Common.LogLevel != nil {
		logLevel = *c.Common.LogLevel
	} else {
		logLevel = log.InfoLevel
	}

	if c.API.Server.PapiLogLevel == nil {
		c.API.Server.PapiLogLevel = &logLevel
	}

	if c.API.Server.OnlineClient != nil && c.API.Server.OnlineClient.CredentialsFilePath != "" {
		if err := c.API.Server.OnlineClient.Load(); err != nil {
			return fmt.Errorf("loading online client credentials: %w", err)
		}
	}

	if (c.API.Server.OnlineClient == nil || c.API.Server.OnlineClient.Credentials == nil) && !inCli {
		log.Printf("push and pull to Central API disabled")
	}

	// Set default values for CAPI push/pull
	if c.API.Server.OnlineClient != nil {
		if c.API.Server.OnlineClient.PullConfig.Community == nil {
			c.API.Server.OnlineClient.PullConfig.Community = ptr.Of(true)
		}

		if c.API.Server.OnlineClient.PullConfig.Blocklists == nil {
			c.API.Server.OnlineClient.PullConfig.Blocklists = ptr.Of(true)
		}

		if c.API.Server.OnlineClient.Sharing == nil {
			c.API.Server.OnlineClient.Sharing = ptr.Of(true)
		}
	}

	if err := c.LoadDBConfig(inCli); err != nil {
		return err
	}

	if err := c.API.Server.LoadCapiWhitelists(); err != nil {
		return err
	}

	if c.API.Server.CapiWhitelistsPath != "" && !inCli {
		log.Infof("loaded capi whitelist from %s: %d IPs, %d CIDRs", c.API.Server.CapiWhitelistsPath, len(c.API.Server.CapiWhitelists.Ips), len(c.API.Server.CapiWhitelists.Cidrs))
	}

	if err := c.API.Server.LoadAutoRegister(); err != nil {
		return err
	}

	if c.API.Server.AutoRegister != nil && c.API.Server.AutoRegister.Enable != nil && *c.API.Server.AutoRegister.Enable && !inCli {
		log.Infof("auto LAPI registration enabled for ranges %+v", c.API.Server.AutoRegister.AllowedRanges)
	}

	c.API.Server.LogDir = c.Common.LogDir
	c.API.Server.LogMedia = c.Common.LogMedia
	c.API.Server.CompressLogs = c.Common.CompressLogs
	c.API.Server.LogMaxSize = c.Common.LogMaxSize
	c.API.Server.LogMaxAge = c.Common.LogMaxAge
	c.API.Server.LogFormat = c.Common.LogFormat
	c.API.Server.LogMaxFiles = c.Common.LogMaxFiles

	if c.API.Server.UseForwardedForHeaders && c.API.Server.TrustedProxies == nil {
		c.API.Server.TrustedProxies = &[]string{"0.0.0.0/0"}
	}

	if c.API.Server.TrustedProxies != nil {
		c.API.Server.UseForwardedForHeaders = true
	}

	if err := c.API.Server.LoadProfiles(); err != nil {
		return fmt.Errorf("while loading profiles for LAPI: %w", err)
	}

	if c.API.Server.ConsoleConfigPath == "" {
		c.API.Server.ConsoleConfigPath = DefaultConsoleConfigFilePath
	}

	if err := c.API.Server.LoadConsoleConfig(); err != nil {
		return fmt.Errorf("while loading console options: %w", err)
	}

	if c.API.CTI != nil {
		if err := c.API.CTI.Load(); err != nil {
			return fmt.Errorf("loading CTI configuration: %w", err)
		}
	}

	return nil
}

// we cannot unmarshal to type net.IPNet, so we need to do it manually
type capiWhitelists struct {
	Ips   []string `yaml:"ips"`
	Cidrs []string `yaml:"cidrs"`
}

func parseCapiWhitelists(fd io.Reader) (*CapiWhitelist, error) {
	fromCfg := capiWhitelists{}

	decoder := yaml.NewDecoder(fd)
	if err := decoder.Decode(&fromCfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty file")
		}

		return nil, err
	}

	ret := &CapiWhitelist{
		Ips:   make([]net.IP, len(fromCfg.Ips)),
		Cidrs: make([]*net.IPNet, len(fromCfg.Cidrs)),
	}

	for idx, v := range fromCfg.Ips {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", v)
		}

		ret.Ips[idx] = ip
	}

	for idx, v := range fromCfg.Cidrs {
		_, tnet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}

		ret.Cidrs[idx] = tnet
	}

	return ret, nil
}

func (c *LocalApiServerCfg) LoadCapiWhitelists() error {
	if c.CapiWhitelistsPath == "" {
		return nil
	}

	fd, err := os.Open(c.CapiWhitelistsPath)
	if err != nil {
		return fmt.Errorf("while opening capi whitelist file: %w", err)
	}

	defer fd.Close()

	c.CapiWhitelists, err = parseCapiWhitelists(fd)
	if err != nil {
		return fmt.Errorf("while parsing capi whitelist file '%s': %w", c.CapiWhitelistsPath, err)
	}

	return nil
}

func (c *Config) LoadAPIClient() error {
	if c.API == nil || c.API.Client == nil || c.API.Client.CredentialsFilePath == "" || c.DisableAgent {
		return errors.New("no API client section in configuration")
	}

	return c.API.Client.Load()
}

func (c *LocalApiServerCfg) LoadAutoRegister() error {
	if c.AutoRegister == nil {
		c.AutoRegister = &LocalAPIAutoRegisterCfg{
			Enable: ptr.Of(false),
		}

		return nil
	}

	// Disable by default
	if c.AutoRegister.Enable == nil {
		c.AutoRegister.Enable = ptr.Of(false)
	}

	if !*c.AutoRegister.Enable {
		return nil
	}

	if c.AutoRegister.Token == "" {
		return errors.New("missing token value for api.server.auto_register")
	}

	if len(c.AutoRegister.Token) < 32 {
		return errors.New("token value for api.server.auto_register is too short (min 32 characters)")
	}

	if c.AutoRegister.AllowedRanges == nil {
		return errors.New("missing allowed_ranges value for api.server.auto_register")
	}

	c.AutoRegister.AllowedRangesParsed = make([]*net.IPNet, 0, len(c.AutoRegister.AllowedRanges))

	for _, ipRange := range c.AutoRegister.AllowedRanges {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return fmt.Errorf("auto_register: failed to parse allowed range '%s': %w", ipRange, err)
		}

		c.AutoRegister.AllowedRangesParsed = append(c.AutoRegister.AllowedRangesParsed, ipNet)
	}

	return nil
}
