package csconfig

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

type DatabaseCfg struct {
	User     string      `yaml:"user"`
	Password string      `yaml:"password"`
	DbName   string      `yaml:"db_name"`
	Host     string      `yaml:"host"`
	Port     int         `yaml:"port"`
	DbPath   string      `yaml:"db_path"`
	Type     string      `yaml:"type"`
	Flush    *FlushDBCfg `yaml:"flush"`
	LogLevel *log.Level  `yaml:"log_level"`
}

type FlushDBCfg struct {
	MaxItems *int    `yaml:"max_items"`
	MaxAge   *string `yaml:"max_age"`
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
