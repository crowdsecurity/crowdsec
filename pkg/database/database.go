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
	Type     string
	WalMode  *bool
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
		}
		//Always try to set permissions to simplify a bit the code for windows (as the permissions set by OpenFile will be garbage)
		if err := setFilePerm(config.DbPath, 0640); err != nil {
			return &Client{}, fmt.Errorf("unable to set perms on %s: %v", config.DbPath, err)
		}
		var sqliteConnectionStringParameters string
		if config.UseWal != nil && *config.UseWal {
			sqliteConnectionStringParameters = "_busy_timeout=100000&_fk=1&_journal_mode=WAL"
		} else {
			sqliteConnectionStringParameters = "_busy_timeout=100000&_fk=1"
		}
		drv, err := getEntDriver("sqlite3", dialect.SQLite, fmt.Sprintf("file:%s?%s", config.DbPath, sqliteConnectionStringParameters), config)
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
	return &Client{Ent: client, CTX: context.Background(), Log: clog, CanFlush: true, Type: config.Type, WalMode: config.UseWal}, nil
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

	// Init & Start cronjob every minute for alerts
	scheduler := gocron.NewScheduler(time.UTC)
	job, err := scheduler.Every(1).Minute().Do(c.FlushAlerts, maxAge, maxItems)
	if err != nil {
		return nil, errors.Wrap(err, "while starting FlushAlerts scheduler")
	}
	job.SingletonMode()
	// Init & Start cronjob every hour for bouncers/agents
	if config.AgentsGC != nil {
		if config.AgentsGC.Cert != nil {
			duration, err := types.ParseDuration(*config.AgentsGC.Cert)
			if err != nil {
				return nil, errors.Wrap(err, "while parsing agents cert auto-delete duration")
			}
			config.AgentsGC.CertDuration = &duration
		}
		if config.AgentsGC.LoginPassword != nil {
			duration, err := types.ParseDuration(*config.AgentsGC.LoginPassword)
			if err != nil {
				return nil, errors.Wrap(err, "while parsing agents login/password auto-delete duration")
			}
			config.AgentsGC.LoginPasswordDuration = &duration
		}
		if config.AgentsGC.Api != nil {
			log.Warning("agents auto-delete for API auth is not supported (use cert or login_password)")
		}
	}
	if config.BouncersGC != nil {
		if config.BouncersGC.Cert != nil {
			duration, err := types.ParseDuration(*config.BouncersGC.Cert)
			if err != nil {
				return nil, errors.Wrap(err, "while parsing bouncers cert auto-delete duration")
			}
			config.BouncersGC.CertDuration = &duration
		}
		if config.BouncersGC.Api != nil {
			duration, err := types.ParseDuration(*config.BouncersGC.Api)
			if err != nil {
				return nil, errors.Wrap(err, "while parsing bouncers api auto-delete duration")
			}
			config.BouncersGC.ApiDuration = &duration
		}
		if config.BouncersGC.LoginPassword != nil {
			log.Warning("bouncers auto-delete for login/password auth is not supported (use cert or api)")
		}
	}
	baJob, err := scheduler.Every(1).Minute().Do(c.FlushAgentsAndBouncers, config.AgentsGC, config.BouncersGC)
	if err != nil {
		return nil, errors.Wrap(err, "while starting FlushAgentsAndBouncers scheduler")
	}
	baJob.SingletonMode()
	scheduler.StartAsync()

	return scheduler, nil
}
