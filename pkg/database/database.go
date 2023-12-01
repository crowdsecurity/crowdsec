package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v4/stdlib"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Client struct {
	Ent              *ent.Client
	CTX              context.Context
	Log              *log.Logger
	CanFlush         bool
	Type             string
	WalMode          *bool
	decisionBulkSize int
}

func getEntDriver(dbtype string, dbdialect string, dsn string, config *csconfig.DatabaseCfg) (*entsql.Driver, error) {
	db, err := sql.Open(dbtype, dsn)
	if err != nil {
		return nil, err
	}
	if config.MaxOpenConns == nil {
		log.Warningf("MaxOpenConns is 0, defaulting to %d", csconfig.DEFAULT_MAX_OPEN_CONNS)
		config.MaxOpenConns = ptr.Of(csconfig.DEFAULT_MAX_OPEN_CONNS)
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
		return nil, fmt.Errorf("while configuring db logger: %w", err)
	}
	if config.LogLevel != nil {
		clog.SetLevel(*config.LogLevel)
	}
	entLogger := clog.WithField("context", "ent")

	entOpt := ent.Log(entLogger.Debug)
	typ, dia, err := config.ConnectionDialect()
	if err != nil {
		return &Client{}, err //unsupported database caught here
	}
	if config.Type == "sqlite" {
		/*if it's the first startup, we want to touch and chmod file*/
		if _, err := os.Stat(config.DbPath); os.IsNotExist(err) {
			f, err := os.OpenFile(config.DbPath, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return &Client{}, fmt.Errorf("failed to create SQLite database file %q: %w", config.DbPath, err)
			}
			if err := f.Close(); err != nil {
				return &Client{}, fmt.Errorf("failed to create SQLite database file %q: %w", config.DbPath, err)
			}
		}
		//Always try to set permissions to simplify a bit the code for windows (as the permissions set by OpenFile will be garbage)
		if err := setFilePerm(config.DbPath, 0640); err != nil {
			return &Client{}, fmt.Errorf("unable to set perms on %s: %v", config.DbPath, err)
		}
	}
	drv, err := getEntDriver(typ, dia, config.ConnectionString(), config)
	if err != nil {
		return &Client{}, fmt.Errorf("failed opening connection to %s: %v", config.Type, err)
	}
	client = ent.NewClient(ent.Driver(drv), entOpt)
	if config.LogLevel != nil && *config.LogLevel >= log.DebugLevel {
		clog.Debugf("Enabling request debug")
		client = client.Debug()
	}
	if err = client.Schema.Create(context.Background()); err != nil {
		return nil, fmt.Errorf("failed creating schema resources: %v", err)
	}

	return &Client{
		Ent: client,
		CTX: context.Background(),
		Log: clog,
		CanFlush: true,
		Type: config.Type,
		WalMode: config.UseWal,
		decisionBulkSize: config.DecisionBulkSize,
	}, nil
}
