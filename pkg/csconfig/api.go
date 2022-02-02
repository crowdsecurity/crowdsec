package csconfig

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type APICfg struct {
	Client *LocalApiClientCfg `yaml:"client"`
	Server *LocalApiServerCfg `yaml:"server"`
}

type ApiCredentialsCfg struct {
	URL      string `yaml:"url,omitempty" json:"url,omitempty"`
	Login    string `yaml:"login,omitempty" json:"login,omitempty"`
	Password string `yaml:"password,omitempty" json:"-"`
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

func (o *OnlineApiClientCfg) Load() error {
	o.Credentials = new(ApiCredentialsCfg)
	fcontent, err := ioutil.ReadFile(o.CredentialsFilePath)
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
	fcontent, err := ioutil.ReadFile(l.CredentialsFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to read api client credential configuration file '%s'", l.CredentialsFilePath)
	}
	err = yaml.UnmarshalStrict(fcontent, &l.Credentials)
	if err != nil {
		return errors.Wrapf(err, "failed unmarshaling api client credential configuration file '%s'", l.CredentialsFilePath)
	}
	if l.Credentials != nil && l.Credentials.URL != "" {
		if !strings.HasSuffix(l.Credentials.URL, "/") {
			l.Credentials.URL = l.Credentials.URL + "/"
		}
	} else {
		log.Warningf("no credentials or URL found in api client configuration '%s'", l.CredentialsFilePath)
	}
	if l.InsecureSkipVerify == nil {
		apiclient.InsecureSkipVerify = false
	} else {
		apiclient.InsecureSkipVerify = *l.InsecureSkipVerify
	}
	return nil
}

/*local api service configuration*/
type LocalApiServerCfg struct {
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
}

type TLSCfg struct {
	CertFilePath string `yaml:"cert_file"`
	KeyFilePath  string `yaml:"key_file"`
}

func (c *Config) LoadAPIServer() error {
	if c.API.Server != nil && !c.DisableAPI {
		if err := c.LoadCommon(); err != nil {
			return fmt.Errorf("loading common configuration: %s", err.Error())
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
		if err := c.LoadDBConfig(); err != nil {
			return err
		}
	} else {
		log.Warningf("crowdsec local API is disabled")
		c.DisableAPI = true
	}

	return nil
}

func (c *Config) LoadAPIClient() error {
	if c.API != nil && c.API.Client != nil && c.API.Client.CredentialsFilePath != "" && !c.DisableAgent {
		if err := c.API.Client.Load(); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no API client section in configuration")
	}

	return nil
}
