package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	entsql "entgo.io/ent/dialect/sql"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
)

type Client struct {
	Ent              *ent.Client
	Log              logging.ExtLogger
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

	if config.MaxOpenConns == 0 {
		config.MaxOpenConns = csconfig.DEFAULT_MAX_OPEN_CONNS
	}

	db.SetMaxOpenConns(config.MaxOpenConns)
	drv := entsql.OpenDB(dbdialect, db)

	return drv, nil
}

func NewClient(ctx context.Context, config *csconfig.DatabaseCfg, logger *log.Entry) (*Client, error) {
	var client *ent.Client

	if logger == nil {
		logger = log.StandardLogger().WithFields(nil)
	}

	if config == nil {
		return nil, errors.New("DB config is empty")
	}

	entLogger := logger.WithField("context", "ent")
	entOpt := ent.Log(entLogger.Debug)

	typ, dia, err := config.ConnectionDialect()
	if err != nil {
		return nil, err // unsupported database caught here
	}

	if config.Type == "sqlite" && config.DbPath != ":memory:" {
		/*if it's the first startup, we want to touch and chmod file*/
		if _, err = os.Stat(config.DbPath); os.IsNotExist(err) {
			f, err := os.OpenFile(config.DbPath, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				return nil, fmt.Errorf("failed to create SQLite database file %q: %w", config.DbPath, err)
			}

			if err := f.Close(); err != nil {
				return nil, fmt.Errorf("failed to create SQLite database file %q: %w", config.DbPath, err)
			}
		}
		// Always try to set permissions to simplify a bit the code for windows (as the permissions set by OpenFile will be garbage)
		if err = setFilePerm(config.DbPath, 0o640); err != nil {
			return nil, fmt.Errorf("unable to set perms on %s: %w", config.DbPath, err)
		}
	}

	dbConnectionString, err := config.ConnectionString()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DB connection string: %w", err)
	}

	drv, err := getEntDriver(typ, dia, dbConnectionString, config)
	if err != nil {
		return nil, fmt.Errorf("failed opening connection to %s: %w", config.Type, err)
	}

	client = ent.NewClient(ent.Driver(drv), entOpt)

	if config.LogLevel >= log.DebugLevel {
		logger.Debugf("Enabling request debug")

		client = client.Debug()
	}

	if err = client.Schema.Create(ctx); err != nil {
		return nil, fmt.Errorf("failed creating schema resources: %w", err)
	}

	return &Client{
		Ent:              client,
		Log:              logger,
		CanFlush:         true,
		Type:             config.Type,
		WalMode:          config.UseWal,
		decisionBulkSize: config.DecisionBulkSize,
	}, nil
}

func (c *Client) Close() error {
	return c.Ent.Close()
}
