package csconfig

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

//var GConfig *GlobalConfig

/*top-level config : defaults,overriden by cfg file,overriden by cli*/
type GlobalConfig struct {
	//just a path to ourself :p
	Self       *string             `yaml:"-"`
	Daemon     *DaemonCfg          `yaml:"common,omitempty"`
	Prometheus *PrometheusCfg      `yaml:"prometheus,omitempty"`
	Crowdsec   *CrowdsecServiceCfg `yaml:"crowdsec_service,omitempty"`
	Cscli      *CscliCfg           `yaml:"cscli,omitempty"`
	Lapi       *LapiServiceCfg     `yaml:"localapi_service,omitempty"`
	LapiClient *LocalApiClientCfg  `yaml:"api_client,omitempty"`
	DbConfig   *DatabaseCfg        `yaml:"db_config,omitempty"`
	ApiClient  *OnlineApiClientCfg `yaml:"online_api_client,omitempty"`
}

type DatabaseCfg struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DbName   string `yaml:"db_name"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	DbPath   string `yaml:"db_path"`
	Type     string `yaml:"type"`
}

/*daemonization/service related stuff*/
type DaemonCfg struct {
	Daemonize  bool
	PidDir     string    `yaml:"pid_dir"`
	LogMedia   string    `yaml:"log_media"`
	LogDir     string    `yaml:"log_dir,omitempty"` //if LogMedia = file
	LogLevel   log.Level `yaml:"log_level"`
	WorkingDir string    `yaml:"working_dir,omitempty"` ///var/run
}

/**/
type PrometheusCfg struct {
	Enabled bool
	Level   string //aggregated|full
}

/*Configurations needed for crowdsec to load parser/scenarios/... + acquisition*/
type CrowdsecServiceCfg struct {
	AcquisitionFilePath string            `yaml:"acquisition_path,omitempty"`
	ParserRoutinesCount int               `yaml:"parser_routines"`
	SimulationFilePath  string            `yaml:"simulation_path,omitempty"`
	SimulationConfig    *SimulationConfig `yaml:"-"`
	LintOnly            bool              `yaml:"-"` //if set to true, exit after loading configs
	ConfigDir           string            `yaml:"config_dir"`
	DataDir             string            `yaml:"data_dir,omitempty"`
	BucketStateFile     string            `yaml:"state_input_file,omitempty"` //if we need to unserialize buckets at start
	BucketStateDumpDir  string            `yaml:"state_output_dir,omitempty"` //if we need to unserialize buckets on shutdown
	BucketsGCEnabled    bool              `yaml:"-"`                          //we need to garbage collect buckets when in forensic mode

}

type ApiCredentialsConfig struct {
	Url      string `yaml:"url,omitempty"`
	Login    string `yaml:"login,omitempty"`
	Password string `yaml:"password,omitempty"`
}

/*global api config (for lapi->oapi)*/
type OnlineApiClientCfg struct {
	CredentialsFilePath string                `yaml:"credentials_path,omitempty"` //credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsConfig `yaml:"-"`
}

/*local api config (for crowdsec/cscli->lapi)*/
type LocalApiClientCfg struct {
	CredentialsFilePath string                `yaml:"credentials_path,omitempty"` //credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsConfig `yaml:"-"`
}

/*local api service configuration*/
type LapiServiceCfg struct {
	CertFilePath string       `yaml:"cert_path,omitempty"`
	ListenUri    string       `yaml:"listen_uri,omitempty"` //127.0.0.1:4242
	DbConfig     *DatabaseCfg `yaml:"-"`
	LogDir       string       `yaml:"-"`
}

/*cscli specific config, such as hub directory*/
type CscliCfg struct {
	HubDir     string `yaml:"hub_dir,omitempty"`
	Output     string `yaml:"output,omitempty"`
	IndexPath  string `yaml:"index_path,omitempty"` //path the the .index.json
	InstallDir string `yaml:"install_dir,omitempty"`
	DataDir    string `yaml:"data_dir,omitempty"`
	/*InstallDir and DataDir are used by both crowdsec and cscli, how to handle it ?*/

	DbConfig *DatabaseCfg `yaml:"-"`
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
	if err := c.LoadSubConfigurations(); err != nil {
		return errors.Wrap(err, "failed to load sub configurations")
	}
	if err := c.CleanupPaths(); err != nil {
		return errors.Wrap(err, "invalid config")
	}
	c.Cscli.DbConfig = c.DbConfig
	c.Lapi.DbConfig = c.DbConfig
	c.Lapi.LogDir = c.Daemon.LogDir
	return nil
}

func (c *GlobalConfig) LoadSubConfigurations() error {
	if c.LapiClient != nil && c.LapiClient.CredentialsFilePath != "" {
		fcontent, err := ioutil.ReadFile(c.LapiClient.CredentialsFilePath)
		if err != nil {
			return errors.Wrap(err, "failed to read config file")
		}
		err = yaml.UnmarshalStrict(fcontent, c.LapiClient.Credentials)
		if err != nil {
			return errors.Wrap(err, "failed unmarshaling config")
		}
	}
	if c.ApiClient != nil && c.ApiClient.CredentialsFilePath != "" {
		fcontent, err := ioutil.ReadFile(c.ApiClient.CredentialsFilePath)
		if err != nil {
			return errors.Wrap(err, "failed to read config file")
		}
		err = yaml.UnmarshalStrict(fcontent, c.ApiClient.Credentials)
		if err != nil {
			return errors.Wrap(err, "failed unmarshaling config")
		}
	}
	return nil
}

func (c *GlobalConfig) LoadSimulation() error {

	if c.Crowdsec == nil || c.Crowdsec.SimulationFilePath == "" {
		return nil
	}
	rcfg, err := ioutil.ReadFile(c.Crowdsec.SimulationFilePath)
	if err != nil {
		return fmt.Errorf("while reading '%s' : %s", c.Crowdsec.SimulationFilePath, err)
	}
	simCfg := SimulationConfig{}
	if err := yaml.UnmarshalStrict(rcfg, &simCfg); err != nil {
		return fmt.Errorf("while parsing '%s' : %s", c.Crowdsec.SimulationFilePath, err)
	}
	c.Crowdsec.SimulationConfig = &simCfg

	return nil
}

func NewConfig() *GlobalConfig {
	cfg := GlobalConfig{}
	return &cfg
}

func NewDefaultConfig() *GlobalConfig {
	daemonCfg := DaemonCfg{
		Daemonize: false,
		PidDir:    "/tmp/",
		LogMedia:  "stdout",
		//LogDir unneeded
		LogLevel:   log.InfoLevel,
		WorkingDir: ".",
	}
	cscli := CscliCfg{
		HubDir:    "/etc/crowdsec/config/cscli/hub/",
		IndexPath: "/etc/crowdsec/config/cscli/.index.json",
		Output:    "human",
	}
	prometheus := PrometheusCfg{
		Enabled: true,
		Level:   "full",
	}
	crowdsecCfg := CrowdsecServiceCfg{
		AcquisitionFilePath: "/etc/crowdsec/config/acquis.yaml",
		ParserRoutinesCount: 1,
		SimulationFilePath:  "/etc/crowdsec/config/simulation.yaml",
		ConfigDir:           "/etc/crowdsec/",
	}
	lapiCfg := LapiServiceCfg{
		CertFilePath: "", //no cert by default ?
		ListenUri:    "http://127.0.0.1:4242/",
	}
	lapiClientCfg := LocalApiClientCfg{
		CredentialsFilePath: "/etc/crowdsec/config/lapi-secrets.yaml",
	}
	oapiClientCfg := OnlineApiClientCfg{
		CredentialsFilePath: "/etc/crowdsec/config/online-api-secrets.yaml",
	}
	globalCfg := GlobalConfig{
		Daemon:     &daemonCfg,
		Prometheus: &prometheus,
		Crowdsec:   &crowdsecCfg,
		Lapi:       &lapiCfg,
		LapiClient: &lapiClientCfg,
		ApiClient:  &oapiClientCfg,
		Cscli:      &cscli,
	}
	return &globalCfg
}

func (c *GlobalConfig) CleanupPaths() error {
	var err error

	var daemon_cleanup = []*string{
		&c.Daemon.PidDir,
		&c.Daemon.LogDir,
		&c.Daemon.WorkingDir,
	}
	if c.Daemon != nil {
		for _, k := range daemon_cleanup {
			*k, err = filepath.Abs(*k)
			if err != nil {
				return errors.Wrap(err, "failed to clean path")
			}
		}
	}

	var crowdsec_cleanup = []*string{
		&c.Crowdsec.AcquisitionFilePath,
		&c.Crowdsec.SimulationFilePath,
		&c.Crowdsec.ConfigDir,
		&c.Crowdsec.DataDir,
	}
	if c.Crowdsec != nil {
		for _, k := range crowdsec_cleanup {
			*k, err = filepath.Abs(*k)
			if err != nil {
				return errors.Wrap(err, "failed to clean path")
			}
		}
	}

	var cscli_cleanup = []*string{
		&c.Cscli.HubDir,
		&c.Cscli.IndexPath,
		&c.Cscli.InstallDir,
		&c.Cscli.DataDir,
	}
	if c.Cscli != nil {
		for _, k := range cscli_cleanup {
			*k, err = filepath.Abs(*k)
			if err != nil {
				return errors.Wrap(err, "failed to clean path")
			}
		}
	}

	return nil
}
