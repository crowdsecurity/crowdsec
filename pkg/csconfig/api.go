package csconfig

import (
	"fmt"
	"io/ioutil"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type APICfg struct {
	Client *LocalApiClientCfg `yaml:"client"`
	Server *LocalApiServerCfg `yaml:"server"`
}

type ApiCredentialsCfg struct {
	URL      string `yaml:"url,omitempty"`
	Login    string `yaml:"login,omitempty"`
	Password string `yaml:"password,omitempty"`
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

/*local api service configuration*/
type LocalApiServerCfg struct {
	ListenURI    string              `yaml:"listen_uri,omitempty"` //127.0.0.1:8080
	TLS          *TLSCfg             `yaml:"tls"`
	DbConfig     *DatabaseCfg        `yaml:"-"`
	LogDir       string              `yaml:"-"`
	OnlineClient *OnlineApiClientCfg `yaml:"online_client"`
	ProfilesPath string              `yaml:"profiles_path,omitempty"`
	Profiles     []*ProfileCfg       `yaml:"-"`
}

type TLSCfg struct {
	CertFilePath string `yaml:"cert_file"`
	KeyFilePath  string `yaml:"key_file"`
}

func (c *LocalApiServerCfg) LoadProfiles() error {
	if c.ProfilesPath == "" {
		return fmt.Errorf("empty profiles path")
	}
	rcfg, err := ioutil.ReadFile(c.ProfilesPath)
	if err != nil {
		return errors.Wrapf(err, "while reading '%s'", c.ProfilesPath)
	} else {
		if err := yaml.UnmarshalStrict(rcfg, &c.Profiles); err != nil {
			return errors.Wrapf(err, "while unmarshaling profiles file '%s'", c.ProfilesPath)
		}
	}

	for pIdx, profile := range c.Profiles {
		var runtimeFilter *vm.Program
		c.Profiles[pIdx].RuntimeFilters = make([]*vm.Program, 0, len(profile.Filters))
		for fIdx, filter := range profile.Filters {
			if runtimeFilter, err = expr.Compile(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"alert": &models.Alert{}}))); err != nil {
				return fmt.Errorf("Error compiling the scope filter: %s", err)
			}
			c.Profiles[pIdx].RuntimeFilters[fIdx] = runtimeFilter
		}

	}
	return nil
}
