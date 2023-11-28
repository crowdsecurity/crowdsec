package csconfig

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

const (
	DEFAULT_MAX_OPEN_CONNS  = 100
	defaultDecisionBulkSize = 1000
	// we need an upper bound due to the sqlite limit of 32k variables in a query
	// we have 15 variables per decision, so 32768/15 = 2184.5333
	maxDecisionBulkSize = 2000
)

type DatabaseCfg struct {
	User             string      `yaml:"user"`
	Password         string      `yaml:"password"`
	DbName           string      `yaml:"db_name"`
	Sslmode          string      `yaml:"sslmode"`
	Host             string      `yaml:"host"`
	Port             int         `yaml:"port"`
	DbPath           string      `yaml:"db_path"`
	Type             string      `yaml:"type"`
	Flush            *FlushDBCfg `yaml:"flush"`
	LogLevel         *log.Level  `yaml:"log_level"`
	MaxOpenConns     *int        `yaml:"max_open_conns,omitempty"`
	UseWal           *bool       `yaml:"use_wal,omitempty"`
	DecisionBulkSize int         `yaml:"decision_bulk_size,omitempty"`
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

	if c.Cscli != nil {
		c.Cscli.DbConfig = c.DbConfig
	}

	if c.API != nil && c.API.Server != nil {
		c.API.Server.DbConfig = c.DbConfig
	}

	if c.DbConfig.MaxOpenConns == nil {
		c.DbConfig.MaxOpenConns = ptr.Of(DEFAULT_MAX_OPEN_CONNS)
	}

	if c.DbConfig.DecisionBulkSize == 0 {
		log.Tracef("No decision_bulk_size value provided, using default value of %d", defaultDecisionBulkSize)
		c.DbConfig.DecisionBulkSize = defaultDecisionBulkSize
	}

	if c.DbConfig.DecisionBulkSize > maxDecisionBulkSize {
		log.Warningf("decision_bulk_size too high (%d), setting to the maximum value of %d", c.DbConfig.DecisionBulkSize, maxDecisionBulkSize)
		c.DbConfig.DecisionBulkSize = maxDecisionBulkSize
	}

	if c.DbConfig.Type == "sqlite" {
		if c.DbConfig.UseWal == nil {
			log.Warning("You are using sqlite without WAL, this can have a performance impact. If you do not store the database in a network share, set db_config.use_wal to true. Set explicitly to false to disable this warning.")
		}
	}

	return nil
}

func (d *DatabaseCfg) ConnectionString() string {
	connString := ""
	switch d.Type {
	case "sqlite":
		var sqliteConnectionStringParameters string
		if d.UseWal != nil && *d.UseWal {
			sqliteConnectionStringParameters = "_busy_timeout=100000&_fk=1&_journal_mode=WAL"
		} else {
			sqliteConnectionStringParameters = "_busy_timeout=100000&_fk=1"
		}
		connString = fmt.Sprintf("file:%s?%s", d.DbPath, sqliteConnectionStringParameters)
	case "mysql":
		if d.isSocketConfig() {
			connString = fmt.Sprintf("%s:%s@unix(%s)/%s?parseTime=True", d.User, d.Password, d.DbPath, d.DbName)
		} else {
			connString = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=True", d.User, d.Password, d.Host, d.Port, d.DbName)
		}
	case "postgres", "postgresql", "pgx":
		if d.isSocketConfig() {
			connString = fmt.Sprintf("host=%s user=%s dbname=%s password=%s", d.DbPath, d.User, d.DbName, d.Password)
		} else {
			connString = fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s", d.Host, d.Port, d.User, d.DbName, d.Password, d.Sslmode)
		}
	}
	return connString
}

func (d *DatabaseCfg) ConnectionDialect() (string, string, error) {
	switch d.Type {
	case "sqlite":
		return "sqlite3", dialect.SQLite, nil
	case "mysql":
		return "mysql", dialect.MySQL, nil
	case "pgx", "postgresql", "postgres":
		if d.Type != "pgx" {
			log.Debugf("database type '%s' is deprecated, switching to 'pgx' instead", d.Type)
		}
		return "pgx", dialect.Postgres, nil
	}
	return "", "", fmt.Errorf("unknown database type '%s'", d.Type)
}

func (d *DatabaseCfg) isSocketConfig() bool {
	return d.Host == "" && d.Port == 0 && d.DbPath != ""
}
