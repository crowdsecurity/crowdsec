package csconfig

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

/*top-level config : defaults,overriden by cfg file,overriden by cli*/
type GlobalConfig struct {
	//just a path to ourself :p
	Self        *string             `yaml:"-"`
	Common      *CommonCfg          `yaml:"common,omitempty"`
	Prometheus  *PrometheusCfg      `yaml:"prometheus,omitempty"`
	Crowdsec    *CrowdsecServiceCfg `yaml:"crowdsec_service,omitempty"`
	Cscli       *CscliCfg           `yaml:"cscli,omitempty"`
	DbConfig    *DatabaseCfg        `yaml:"db_config,omitempty"`
	API         *APICfg             `yaml:"api,omitempty"`
	ConfigPaths *ConfigurationPaths `yaml:"config_paths,omitempty"`
}

func (c *GlobalConfig) Dump() error {
	out, err := yaml.Marshal(c)
	if err != nil {
		return errors.Wrap(err, "failed marshaling config")
	}
	fmt.Printf("%s", string(out))
	return nil
}

func (c *GlobalConfig) LoadConfigurationFile(path string) error {

	fcontent, err := ioutil.ReadFile(path)
	if err != nil {
		return errors.Wrap(err, "failed to read config file")
	}
	err = yaml.UnmarshalStrict(fcontent, c)
	if err != nil {
		return errors.Wrap(err, "failed unmarshaling config")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return errors.Wrap(err, "failed to load absolute path")
	}
	c.Self = &path
	if err := c.LoadConfiguration(); err != nil {
		return errors.Wrap(err, "failed to load sub configurations")
	}

	return nil
}

func (c *GlobalConfig) LoadConfiguration() error {
	if c.ConfigPaths.ConfigDir == "" {
		return fmt.Errorf("please provide a configuration directory with the 'config_dir' directive in the 'config_paths' section")
	}

	if c.ConfigPaths.DataDir == "" {
		return fmt.Errorf("please provide a data directory with the 'data_dir' directive in the 'config_paths' section")
	}

	if c.ConfigPaths.HubDir == "" {
		c.ConfigPaths.HubDir = filepath.Clean(c.ConfigPaths.ConfigDir + "/hub")
	}

	if c.ConfigPaths.HubIndexFile == "" {
		c.ConfigPaths.HubIndexFile = filepath.Clean(c.ConfigPaths.HubDir + "/.index.json")
	}

	if err := c.LoadSimulation(); err != nil {
		return err
	}

	if c.Crowdsec != nil {
		if c.Crowdsec.AcquisitionFilePath == "" {
			c.Crowdsec.AcquisitionFilePath = filepath.Clean(c.ConfigPaths.ConfigDir + "/acquis.yaml")
		}
		c.Crowdsec.ConfigDir = c.ConfigPaths.ConfigDir
		c.Crowdsec.DataDir = c.ConfigPaths.DataDir
		c.Crowdsec.HubDir = c.ConfigPaths.HubDir
		c.Crowdsec.HubIndexFile = c.ConfigPaths.HubIndexFile
		if c.Crowdsec.ParserRoutinesCount <= 0 {
			c.Crowdsec.ParserRoutinesCount = 1
		}

		if c.Crowdsec.BucketsRoutinesCount <= 0 {
			c.Crowdsec.BucketsRoutinesCount = 1
		}

		if c.Crowdsec.OutputRoutinesCount <= 0 {
			c.Crowdsec.OutputRoutinesCount = 1
		}
	}

	if err := c.CleanupPaths(); err != nil {
		return errors.Wrap(err, "invalid config")
	}

	if c.Cscli != nil {
		c.Cscli.DbConfig = c.DbConfig
		c.Cscli.ConfigDir = c.ConfigPaths.ConfigDir
		c.Cscli.DataDir = c.ConfigPaths.DataDir
		c.Cscli.HubDir = c.ConfigPaths.HubDir
		c.Cscli.HubIndexFile = c.ConfigPaths.HubIndexFile
	}

	if c.API.Client != nil && c.API.Client.CredentialsFilePath != "" {
		fcontent, err := ioutil.ReadFile(c.API.Client.CredentialsFilePath)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to read api client credential configuration file '%s'", c.API.Client.CredentialsFilePath))
		}
		err = yaml.UnmarshalStrict(fcontent, &c.API.Client.Credentials)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed unmarshaling api client credential configuration file '%s'", c.API.Client.CredentialsFilePath))
		}
		if c.API.Client.Credentials != nil && c.API.Client.Credentials.URL != "" {
			if !strings.HasSuffix(c.API.Client.Credentials.URL, "/") {
				c.API.Client.Credentials.URL = c.API.Client.Credentials.URL + "/"
			}
		}
		if c.API.Client.InsecureSkipVerify == nil {
			apiclient.InsecureSkipVerify = true
		} else {
			apiclient.InsecureSkipVerify = *c.API.Client.InsecureSkipVerify
		}
	}

	if c.API.Server != nil {
		c.API.Server.DbConfig = c.DbConfig
		c.API.Server.LogDir = c.Common.LogDir
		if err := c.API.Server.LoadProfiles(); err != nil {
			return errors.Wrap(err, "while loading profiles for LAPI")
		}
		if c.API.Server.OnlineClient != nil && c.API.Server.OnlineClient.CredentialsFilePath != "" {
			c.API.Server.OnlineClient.Credentials = new(ApiCredentialsCfg)
			fcontent, err := ioutil.ReadFile(c.API.Server.OnlineClient.CredentialsFilePath)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed to read api server credentials configuration file '%s'", c.API.Server.OnlineClient.CredentialsFilePath))
			}
			err = yaml.UnmarshalStrict(fcontent, c.API.Server.OnlineClient.Credentials)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed unmarshaling api server credentials configuration file '%s'", c.API.Server.OnlineClient.CredentialsFilePath))
			}
			if c.API.Server.OnlineClient.Credentials == nil {
				log.Debugf("online credentials not found in '%s', will not use crowdsec api", c.API.Server.OnlineClient.CredentialsFilePath)
			}
		}
	}

	return nil
}

func (c *GlobalConfig) LoadSimulation() error {
	if c.ConfigPaths == nil {
		return fmt.Errorf("ConfigPaths is empty")
	}

	simCfg := SimulationConfig{}

	if c.ConfigPaths.SimulationFilePath == "" {
		c.ConfigPaths.SimulationFilePath = filepath.Clean(c.ConfigPaths.ConfigDir + "/simulation.yaml")
	}

	rcfg, err := ioutil.ReadFile(c.ConfigPaths.SimulationFilePath)
	if err != nil {
		return errors.Wrapf(err, "while reading '%s'", c.ConfigPaths.SimulationFilePath)
	} else {
		if err := yaml.UnmarshalStrict(rcfg, &simCfg); err != nil {
			return fmt.Errorf("while unmarshaling simulation file '%s' : %s", c.ConfigPaths.SimulationFilePath, err)
		}
	}
	if simCfg.Simulation == nil {
		simCfg.Simulation = new(bool)
	}
	if c.Crowdsec != nil {
		c.Crowdsec.SimulationConfig = &simCfg
	}
	if c.Cscli != nil {
		c.Cscli.SimulationConfig = &simCfg
	}
	return nil
}

func NewConfig() *GlobalConfig {
	cfg := GlobalConfig{}
	return &cfg
}

func NewDefaultConfig() *GlobalConfig {
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
			ListenURI: "127.0.0.1:8080",
			OnlineClient: &OnlineApiClientCfg{
				CredentialsFilePath: "/etc/crowdsec/config/online-api-secrets.yaml",
			},
		},
	}

	dbConfig := DatabaseCfg{
		Type:   "sqlite",
		DbPath: "/var/lib/crowdsec/data/crowdsec.db",
	}

	globalCfg := GlobalConfig{
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

func (c *GlobalConfig) CleanupPaths() error {
	var err error

	if c.Common != nil {
		var CommonCleanup = []*string{
			&c.Common.PidDir,
			&c.Common.LogDir,
			&c.Common.WorkingDir,
		}
		for _, k := range CommonCleanup {
			*k, err = filepath.Abs(*k)
			if err != nil {
				return errors.Wrap(err, "failed to clean path")
			}
		}
	}

	if c.Crowdsec != nil {
		var crowdsecCleanup = []*string{
			&c.Crowdsec.AcquisitionFilePath,
		}
		for _, k := range crowdsecCleanup {
			*k, err = filepath.Abs(*k)
			if err != nil {
				return errors.Wrap(err, "failed to clean path")
			}
		}
	}

	if c.ConfigPaths != nil {
		var configPathsCleanup = []*string{
			&c.ConfigPaths.HubDir,
			&c.ConfigPaths.HubIndexFile,
			&c.ConfigPaths.ConfigDir,
			&c.ConfigPaths.DataDir,
			&c.ConfigPaths.SimulationFilePath,
		}
		for _, k := range configPathsCleanup {
			*k, err = filepath.Abs(*k)
			if err != nil {
				return errors.Wrap(err, "failed to clean path")
			}
		}
	}

	return nil
}
