package csconfig

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

/*top-level config : defaults,overriden by cfg file,overriden by cli*/
type Config struct {
	//just a path to ourself :p
	FilePath     *string             `yaml:"-"`
	Self         []byte              `yaml:"-"`
	Common       *CommonCfg          `yaml:"common,omitempty"`
	Prometheus   *PrometheusCfg      `yaml:"prometheus,omitempty"`
	Crowdsec     *CrowdsecServiceCfg `yaml:"crowdsec_service,omitempty"`
	Cscli        *CscliCfg           `yaml:"cscli,omitempty"`
	DbConfig     *DatabaseCfg        `yaml:"db_config,omitempty"`
	API          *APICfg             `yaml:"api,omitempty"`
	ConfigPaths  *ConfigurationPaths `yaml:"config_paths,omitempty"`
	DisableAPI   bool                `yaml:"-"`
	DisableAgent bool                `yaml:"-"`
	Hub          *Hub                `yaml:"-"`
}

func (c *Config) Dump() error {
	out, err := yaml.Marshal(c)
	if err != nil {
		return errors.Wrap(err, "failed marshaling config")
	}
	fmt.Printf("%s", string(out))
	return nil
}

func NewConfig(configFile string, disableAgent bool, disableAPI bool) (*Config, error) {
	fcontent, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read config file")
	}
	configData := os.ExpandEnv(string(fcontent))
	cfg := Config{
		FilePath:     &configFile,
		DisableAgent: disableAgent,
		DisableAPI:   disableAPI,
	}

	err = yaml.UnmarshalStrict([]byte(configData), &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func NewDefaultConfig() *Config {
	logLevel := log.InfoLevel
	CommonCfg := CommonCfg{
		Daemonize: false,
		PidDir:    "/tmp/",
		LogMedia:  "stdout",
		//LogDir unneeded
		LogLevel:   &logLevel,
		WorkingDir: ".",
	}
	prometheus := PrometheusCfg{
		Enabled: true,
		Level:   "full",
	}
	configPaths := ConfigurationPaths{
		ConfigDir:          "/etc/crowdsec/",
		DataDir:            "/var/lib/crowdsec/data/",
		SimulationFilePath: "/etc/crowdsec/config/simulation.yaml",
		HubDir:             "/etc/crowdsec/hub",
		HubIndexFile:       "/etc/crowdsec/hub/.index.json",
	}
	crowdsecCfg := CrowdsecServiceCfg{
		AcquisitionFilePath: "/etc/crowdsec/config/acquis.yaml",
		ParserRoutinesCount: 1,
	}

	cscliCfg := CscliCfg{
		Output: "human",
	}

	apiCfg := APICfg{
		Client: &LocalApiClientCfg{
			CredentialsFilePath: "/etc/crowdsec/config/lapi-secrets.yaml",
		},
		Server: &LocalApiServerCfg{
			ListenURI:              "127.0.0.1:8080",
			UseForwardedForHeaders: false,
			OnlineClient: &OnlineApiClientCfg{
				CredentialsFilePath: "/etc/crowdsec/config/online-api-secrets.yaml",
			},
		},
	}

	dbConfig := DatabaseCfg{
		Type:   "sqlite",
		DbPath: "/var/lib/crowdsec/data/crowdsec.db",
	}

	globalCfg := Config{
		Common:      &CommonCfg,
		Prometheus:  &prometheus,
		Crowdsec:    &crowdsecCfg,
		Cscli:       &cscliCfg,
		API:         &apiCfg,
		ConfigPaths: &configPaths,
		DbConfig:    &dbConfig,
	}

	return &globalCfg
}
