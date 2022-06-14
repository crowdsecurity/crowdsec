package csconfig

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

var DEFAULT_MAX_OPEN_CONNS = 100

type DatabaseCfg struct {
	User         string      `yaml:"user"`
	Password     string      `yaml:"password"`
	DbName       string      `yaml:"db_name"`
	Sslmode      string      `yaml:"sslmode"`
	Host         string      `yaml:"host"`
	Port         int         `yaml:"port"`
	DbPath       string      `yaml:"db_path"`
	Type         string      `yaml:"type"`
	Flush        *FlushDBCfg `yaml:"flush"`
	LogLevel     *log.Level  `yaml:"log_level"`
	MaxOpenConns *int        `yaml:"max_open_conns,omitempty"`
}

type AuthGCCfg struct {
	Cert                  *string `yaml:"cert,omitempty"`
	CertDuration          *time.Duration
	Api                   *string `yaml:"api_key,omitempty"`
	ApiDuration           *time.Duration
	LoginPassword         *string `yaml:"login_password,omitempty"`
	LoginPasswordDuration *time.Duration
}

type FlushDBCfg struct {
	MaxItems   *int       `yaml:"max_items,omitempty"`
	MaxAge     *string    `yaml:"max_age,omitempty"`
	BouncersGC *AuthGCCfg `yaml:"bouncers_autodelete,omitempty"`
	AgentsGC   *AuthGCCfg `yaml:"agents_autodelete,omitempty"`
}

func (c *Config) LoadDBConfig() error {
	if c.DbConfig == nil {
		return fmt.Errorf("no database configuration provided")
	}

	if c.DbConfig.Type == "" {
		c.DbConfig.Type = "sqlite"
		log.Info("Missing database type: defaults to 'sqlite'")
	}

	if c.Cscli != nil {
		c.Cscli.DbConfig = c.DbConfig
	}

	if c.API != nil && c.API.Server != nil {
		c.API.Server.DbConfig = c.DbConfig
	}

	if c.DbConfig.MaxOpenConns == nil {
		c.DbConfig.MaxOpenConns = types.IntPtr(DEFAULT_MAX_OPEN_CONNS)
	}
	return nil
}
