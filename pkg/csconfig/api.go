package csconfig

import (
	"fmt"
	"io"
	"os"

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

	yamlFile, err := os.Open(c.ProfilesPath)
	if err != nil {
		return errors.Wrapf(err, "while opening %s", c.ProfilesPath)
	}

	//process the yaml
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	for {
		t := ProfileCfg{}
		err = dec.Decode(&t)
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrapf(err, "while decoding %s", c.ProfilesPath)
		}
		c.Profiles = append(c.Profiles, &t)
	}

	for pIdx, profile := range c.Profiles {
		var runtimeFilter *vm.Program
		var debugFilter *exprhelpers.ExprDebugger

		c.Profiles[pIdx].RuntimeFilters = make([]*vm.Program, len(profile.Filters))
		c.Profiles[pIdx].DebugFilters = make([]*exprhelpers.ExprDebugger, len(profile.Filters))

		for fIdx, filter := range profile.Filters {
			if runtimeFilter, err = expr.Compile(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
				return fmt.Errorf("Error compiling the scope filter: %s", err)
			}
			c.Profiles[pIdx].RuntimeFilters[fIdx] = runtimeFilter
			//
			if debugFilter, err = exprhelpers.NewDebugger(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
				return fmt.Errorf("Error compiling the debug scope filter: %s", err)
			}
			c.Profiles[pIdx].DebugFilters[fIdx] = debugFilter

		}

	}
	return nil
}
