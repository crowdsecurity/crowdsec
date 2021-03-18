package csconfig

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

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

func (c *Config) LoadAPIServer() error {
	if c.API.Server != nil && !c.DisableAPI {
		if err := c.LoadCommon(); err != nil {
			return fmt.Errorf("loading common configuration: %s", err.Error())
		}
		c.API.Server.LogDir = c.Common.LogDir
		c.API.Server.LogMedia = c.Common.LogMedia
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
			if c.API.Server.OnlineClient.Credentials.Login == "" || c.API.Server.OnlineClient.Credentials.Password == "" || c.API.Server.OnlineClient.Credentials.URL == "" {
				log.Debugf("can't load CAPI credentials from '%s' (missing field)", c.API.Server.OnlineClient.CredentialsFilePath)
				c.API.Server.OnlineClient.Credentials = nil
			}
		}
		if c.API.Server.OnlineClient == nil || c.API.Server.OnlineClient.Credentials == nil {
			log.Printf("push and pull to crowdsec API disabled")
		}
		if err := c.LoadDBConfig(); err != nil {
			return err
		}
	} else {
		c.DisableAPI = true
	}

	return nil
}

func (c *Config) LoadAPIClient() error {
	if c.API.Client != nil && c.API.Client.CredentialsFilePath != "" && !c.DisableAgent {
		if err := c.API.Client.Load(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) LoadConfigurationPaths() error {
	var err error
	if c.ConfigPaths == nil {
		return fmt.Errorf("no configuration paths provided")
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

	var configPathsCleanup = []*string{
		&c.ConfigPaths.HubDir,
		&c.ConfigPaths.HubIndexFile,
		&c.ConfigPaths.ConfigDir,
		&c.ConfigPaths.DataDir,
		&c.ConfigPaths.SimulationFilePath,
	}
	for _, k := range configPathsCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return errors.Wrap(err, "failed to clean path")
		}
	}

	return nil
}

func (c *Config) LoadCrowdsec() error {
	var err error
	// Configuration paths are dependency to load crowdsec configuration
	if c.ConfigPaths == nil {
		if err := c.LoadConfigurationPaths(); err != nil {
			return err
		}
	}

	if c.Crowdsec == nil {
		c.DisableAgent = true
		return nil
	}
	if c.Crowdsec.AcquisitionFilePath != "" {
		log.Debugf("non-empty acquisition file path %s", c.Crowdsec.AcquisitionFilePath)
		if _, err := os.Stat(c.Crowdsec.AcquisitionFilePath); err != nil {
			return errors.Wrapf(err, "while checking acquisition path %s", c.Crowdsec.AcquisitionFilePath)
		}
		c.Crowdsec.AcquisitionFiles = append(c.Crowdsec.AcquisitionFiles, c.Crowdsec.AcquisitionFilePath)
	}
	if c.Crowdsec.AcquisitionDirPath != "" {
		files, err := filepath.Glob(c.Crowdsec.AcquisitionDirPath + "/*.yaml")
		c.Crowdsec.AcquisitionFiles = append(c.Crowdsec.AcquisitionFiles, files...)
		if err != nil {
			return errors.Wrap(err, "while globing acquis_dir")
		}
	}
	if c.Crowdsec.AcquisitionDirPath == "" && c.Crowdsec.AcquisitionFilePath == "" {
		return fmt.Errorf("no acquisition_path nor acquisition_dir")
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

	var crowdsecCleanup = []*string{
		&c.Crowdsec.AcquisitionFilePath,
	}
	for _, k := range crowdsecCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return errors.Wrap(err, "failed to clean path")
		}
	}
	if err := c.LoadAPIClient(); err != nil {
		return fmt.Errorf("loading api client: %s", err.Error())
	}
	if err := c.LoadHub(); err != nil {
		return fmt.Errorf("loading hub: %s", err)
	}
	return nil
}

func (c *Config) LoadPrometheus() error {
	if c.Cscli != nil && c.Cscli.PrometheusUrl == "" && c.Prometheus != nil {
		if c.Prometheus.ListenAddr != "" && c.Prometheus.ListenPort != 0 {
			c.Cscli.PrometheusUrl = fmt.Sprintf("http://%s:%d", c.Prometheus.ListenAddr, c.Prometheus.ListenPort)
		}
	}

	return nil
}

func (c *Config) LoadCSCLI() error {
	if c.ConfigPaths == nil {
		if err := c.LoadConfigurationPaths(); err != nil {
			return err
		}
	}

	c.Cscli.ConfigDir = c.ConfigPaths.ConfigDir
	c.Cscli.DataDir = c.ConfigPaths.DataDir
	c.Cscli.HubDir = c.ConfigPaths.HubDir
	c.Cscli.HubIndexFile = c.ConfigPaths.HubIndexFile

	return nil
}

func (c *Config) LoadHub() error {
	if err := c.LoadConfigurationPaths(); err != nil {
		return err
	}

	c.Hub = &Hub{
		HubIndexFile: c.ConfigPaths.HubIndexFile,
		ConfigDir:    c.ConfigPaths.ConfigDir,
		HubDir:       c.ConfigPaths.HubDir,
		DataDir:      c.ConfigPaths.DataDir,
	}

	return nil
}
func (c *Config) LoadDBConfig() error {
	if c.DbConfig == nil {
		return fmt.Errorf("no database configuration provided")
	}

	if c.Cscli != nil {
		c.Cscli.DbConfig = c.DbConfig
	}

	if c.API.Server != nil {
		c.API.Server.DbConfig = c.DbConfig
	}

	return nil
}

func (c *Config) LoadCommon() error {
	var err error
	if c.Common == nil {
		return fmt.Errorf("no common block provided in configuration file")
	}

	var CommonCleanup = []*string{
		&c.Common.PidDir,
		&c.Common.LogDir,
		&c.Common.WorkingDir,
	}
	for _, k := range CommonCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return errors.Wrap(err, "failed to clean path")
		}
	}

	return nil
}

func (c *Config) LoadSimulation() error {
	if c.ConfigPaths == nil {
		if err := c.LoadConfigurationPaths(); err != nil {
			return err
		}
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
