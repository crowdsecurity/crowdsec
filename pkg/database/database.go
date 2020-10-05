package database

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/go-co-op/gocron"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
)

type Client struct {
	Ent *ent.Client
	CTX context.Context
}

func NewClient(config *csconfig.DatabaseCfg) (*Client, error) {
	var client *ent.Client
	var err error
	switch config.Type {
	case "sqlite":
		client, err = ent.Open("sqlite3", fmt.Sprintf("file:%s?_busy_timeout=100000&_fk=1", config.DbPath))
		if err != nil {
			return &Client{}, fmt.Errorf("failed opening connection to sqlite: %v", err)
		}
	case "mysql":
		client, err = ent.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=True", config.User, config.Password, config.Host, config.Port, config.DbName))
		if err != nil {
			return &Client{}, fmt.Errorf("failed opening connection to mysql: %v", err)
		}
	default:
		return &Client{}, fmt.Errorf("unknown database type")
	}

	if err = client.Schema.Create(context.Background()); err != nil {
		return nil, fmt.Errorf("failed creating schema resources: %v", err)
	}
	return &Client{Ent: client, CTX: context.Background()}, nil
}

func (c *Client) StartFlushScheduler(config *csconfig.FlushDBCfg) (*gocron.Scheduler, error) {
	var durationStr string
	maxAge := time.Duration(0)
	maxItems := 0
	if config.MaxItems != nil && *config.MaxItems <= 0 {
		return nil, fmt.Errorf("max_items can't be zero or negative number")
	}

	maxItems = *config.MaxItems
	if config.MaxAge != nil && *config.MaxAge != "" {
		durationStr = *config.MaxAge
		if strings.HasSuffix(*config.MaxAge, "d") {
			days := strings.Split(*config.MaxAge, "d")[0]
			if len(days) == 0 {
				return nil, fmt.Errorf("max_age (%s) can't be parsed as duration", *config.MaxAge)
			}
			daysInt, err := strconv.Atoi(days)
			if err != nil {
				return nil, errors.Wrapf(err, "max_age (%s) can't be parsed as duration", *config.MaxAge)
			}
			durationStr = strconv.Itoa(daysInt*24) + "h"
		}
		maxDuration, err := time.ParseDuration(durationStr)
		if err != nil {
			return nil, errors.Wrapf(err, "max_age (%s) can't be parsed as duration", *config.MaxAge)
		}
		maxAge = maxDuration
	}
	// Init & Start cronjob every minute
	scheduler := gocron.NewScheduler(time.UTC)
	scheduler.Every(1).Minute().Do(c.FlushAlerts, maxAge, maxItems)
	scheduler.StartAsync()

	return scheduler, nil
}
