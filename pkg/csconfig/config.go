package csconfig

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/csstring"
	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
	"github.com/crowdsecurity/go-cs-lib/pkg/yamlpatch"
)

// defaultConfigDir is the base path to all configuration files, to be overridden in the Makefile */
var defaultConfigDir = "/etc/crowdsec"

// defaultDataDir is the base path to all data files, to be overridden in the Makefile */
var defaultDataDir = "/var/lib/crowdsec/data/"

// Config contains top-level defaults -> overridden by configuration file -> overridden by CLI flags
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
	PluginConfig *PluginCfg          `yaml:"plugin_config,omitempty"`
	DisableAPI   bool                `yaml:"-"`
	DisableAgent bool                `yaml:"-"`
	Hub          *Hub                `yaml:"-"`
}

func (c *Config) Dump() error {
	out, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed marshaling config: %w", err)
	}
	fmt.Printf("%s", string(out))
	return nil
}

func NewConfig(configFile string, disableAgent bool, disableAPI bool, quiet bool) (*Config, string, error) {
	patcher := yamlpatch.NewPatcher(configFile, ".local")
	patcher.SetQuiet(quiet)
	fcontent, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, "", err
	}
	configData := csstring.StrictExpand(string(fcontent), os.LookupEnv)
	cfg := Config{
		FilePath:     &configFile,
		DisableAgent: disableAgent,
		DisableAPI:   disableAPI,
	}

	err = yaml.UnmarshalStrict([]byte(configData), &cfg)
	if err != nil {
		// this is actually the "merged" yaml
		return nil, "", fmt.Errorf("%s: %w", configFile, err)
	}
	return &cfg, configData, nil
}

func NewDefaultConfig() *Config {
	logLevel := log.InfoLevel
	commonCfg := CommonCfg{
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
		ConfigDir:          DefaultConfigPath("."),
		DataDir:            DefaultDataPath("."),
		SimulationFilePath: DefaultConfigPath("simulation.yaml"),
		HubDir:             DefaultConfigPath("hub"),
		HubIndexFile:       DefaultConfigPath("hub", ".index.json"),
	}
	crowdsecCfg := CrowdsecServiceCfg{
		AcquisitionFilePath: DefaultConfigPath("acquis.yaml"),
		ParserRoutinesCount: 1,
	}

	cscliCfg := CscliCfg{
		Output: "human",
		Color:  "auto",
	}

	apiCfg := APICfg{
		Client: &LocalApiClientCfg{
			CredentialsFilePath: DefaultConfigPath("lapi-secrets.yaml"),
		},
		Server: &LocalApiServerCfg{
			ListenURI:              "127.0.0.1:8080",
			UseForwardedForHeaders: false,
			OnlineClient: &OnlineApiClientCfg{
				CredentialsFilePath: DefaultConfigPath("online_api_credentials.yaml"),
			},
		},
		CTI: &CTICfg{
			Enabled: ptr.Of(false),
		},
	}

	dbConfig := DatabaseCfg{
		Type:         "sqlite",
		DbPath:       DefaultDataPath("crowdsec.db"),
		MaxOpenConns: ptr.Of(DEFAULT_MAX_OPEN_CONNS),
	}

	globalCfg := Config{
		Common:      &commonCfg,
		Prometheus:  &prometheus,
		Crowdsec:    &crowdsecCfg,
		Cscli:       &cscliCfg,
		API:         &apiCfg,
		ConfigPaths: &configPaths,
		DbConfig:    &dbConfig,
	}

	return &globalCfg
}

// DefaultConfigPath returns the default path for a configuration resource
// "elem" parameters are path components relative to the default cfg directory.
func DefaultConfigPath(elem ...string) string {
	elem = append([]string{defaultConfigDir}, elem...)
	return filepath.Join(elem...)
}

// DefaultDataPath returns the default path for a data resource.
// "elem" parameters are path components relative to the default data directory.
func DefaultDataPath(elem ...string) string {
	elem = append([]string{defaultDataDir}, elem...)
	return filepath.Join(elem...)
}
