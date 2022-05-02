package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-co-op/gocron"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v4/stdlib"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	Ent      *ent.Client
	CTX      context.Context
	Log      *log.Logger
	CanFlush bool
}

func getEntDriver(dbtype string, dbdialect string, dsn string, config *csconfig.DatabaseCfg) (*entsql.Driver, error) {
	db, err := sql.Open(dbtype, dsn)
	if err != nil {
		return nil, err
	}
	if config.MaxOpenConns == nil {
		log.Warningf("MaxOpenConns is 0, defaulting to %d", csconfig.DEFAULT_MAX_OPEN_CONNS)
		config.MaxOpenConns = types.IntPtr(csconfig.DEFAULT_MAX_OPEN_CONNS)
	}
	db.SetMaxOpenConns(*config.MaxOpenConns)
	drv := entsql.OpenDB(dbdialect, db)
	return drv, nil
}

func NewClient(config *csconfig.DatabaseCfg) (*Client, error) {
	var client *ent.Client
	var err error
	if config == nil {
		return &Client{}, fmt.Errorf("DB config is empty")
	}
	/*The logger that will be used by db operations*/
	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return nil, errors.Wrap(err, "while configuring db logger")
	}
	if config.LogLevel != nil {
		clog.SetLevel(*config.LogLevel)
	}
	entLogger := clog.WithField("context", "ent")

	entOpt := ent.Log(entLogger.Debug)
	switch config.Type {
	case "sqlite":

		/*if it's the first startup, we want to touch and chmod file*/
		if _, err := os.Stat(config.DbPath); os.IsNotExist(err) {
			f, err := os.OpenFile(config.DbPath, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return &Client{}, errors.Wrapf(err, "failed to create SQLite database file %q", config.DbPath)
			}
			if err := f.Close(); err != nil {
				return &Client{}, errors.Wrapf(err, "failed to create SQLite database file %q", config.DbPath)
			}
		} else { /*ensure file perms*/
			if err := os.Chmod(config.DbPath, 0660); err != nil {
				return &Client{}, fmt.Errorf("unable to set perms on %s: %v", config.DbPath, err)
			}
		}
		drv, err := getEntDriver("sqlite3", dialect.SQLite, fmt.Sprintf("file:%s?_busy_timeout=100000&_fk=1", config.DbPath), config)
		if err != nil {
			return &Client{}, errors.Wrapf(err, "failed opening connection to sqlite: %v", config.DbPath)
		}
		client = ent.NewClient(ent.Driver(drv), entOpt)
	case "mysql":
		drv, err := getEntDriver("mysql", dialect.MySQL, fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=True", config.User, config.Password, config.Host, config.Port, config.DbName), config)
		if err != nil {
			return &Client{}, fmt.Errorf("failed opening connection to mysql: %v", err)
		}
		client = ent.NewClient(ent.Driver(drv), entOpt)
	case "postgres", "postgresql":
		drv, err := getEntDriver("postgres", dialect.Postgres, fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s", config.Host, config.Port, config.User, config.DbName, config.Password, config.Sslmode), config)
		if err != nil {
			return &Client{}, fmt.Errorf("failed opening connection to postgresql: %v", err)
		}
		client = ent.NewClient(ent.Driver(drv), entOpt)
	case "pgx":
		drv, err := getEntDriver("pgx", dialect.Postgres, fmt.Sprintf("postgresql://%s:%s@%s:%d/%s?sslmode=%s", config.User, config.Password, config.Host, config.Port, config.DbName, config.Sslmode), config)
		if err != nil {
			return &Client{}, fmt.Errorf("failed opening connection to pgx: %v", err)
		}
		client = ent.NewClient(ent.Driver(drv), entOpt)
	default:
		return &Client{}, fmt.Errorf("unknown database type '%s'", config.Type)
	}

	if config.LogLevel != nil && *config.LogLevel >= log.DebugLevel {
		clog.Debugf("Enabling request debug")
		client = client.Debug()
	}
	if err = client.Schema.Create(context.Background()); err != nil {
		return nil, fmt.Errorf("failed creating schema resources: %v", err)
	}
	return &Client{Ent: client, CTX: context.Background(), Log: clog, CanFlush: true}, nil
}

func (c *Client) StartFlushScheduler(config *csconfig.FlushDBCfg) (*gocron.Scheduler, error) {
	maxItems := 0
	maxAge := ""
	if config.MaxItems != nil && *config.MaxItems <= 0 {
		return nil, fmt.Errorf("max_items can't be zero or negative number")
	}
	if config.MaxItems != nil {
		maxItems = *config.MaxItems
	}

	if config.MaxAge != nil && *config.MaxAge != "" {
		maxAge = *config.MaxAge
	}
	// Init & Start cronjob every minute
	scheduler := gocron.NewScheduler(time.UTC)
	job, _ := scheduler.Every(1).Minute().Do(c.FlushAlerts, maxAge, maxItems)
	job.SingletonMode()
	scheduler.StartAsync()

	return scheduler, nil
}
