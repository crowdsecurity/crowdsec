package database

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/tomb.v2"
)

type Context struct {
	Db         *gorm.DB //Pointer to database
	tx         *gorm.DB //Pointer to current transaction (flushed on a regular basis)
	lastCommit time.Time
	flush      bool
	count      int32
	lock       sync.Mutex //booboo
	PusherTomb tomb.Tomb
}

func checkConfig(cfg map[string]string) error {
	switch dbType, _ := cfg["type"]; dbType {
	case "sqlite":
		if val, ok := cfg["db_path"]; !ok && val == "" {
			return fmt.Errorf("please specify a 'db_path' to SQLite db in the configuration")
		}
	case "mysql":
		if val, ok := cfg["db_host"]; !ok && val == "" {
			return fmt.Errorf("please specify a 'db_host' to SQLite db in the configuration")
		}

		if val, ok := cfg["db_username"]; !ok && val == "" {
			return fmt.Errorf("please specify a 'db_username' to SQLite db in the configuration")
		}

		if val, ok := cfg["db_password"]; !ok && val == "" {
			return fmt.Errorf("please specify a 'db_password' to SQLite db in the configuration")
		}

		if val, ok := cfg["db_name"]; !ok && val == "" {
			return fmt.Errorf("please specify a 'db_name' to SQLite db in the configuration")
		}
	default:
		return fmt.Errorf("please specify a proper 'type' to the database configuration ")
	}

	return nil
}

func NewDatabase(cfg map[string]string) (*Context, error) {
	var err error
	c := &Context{}

	if err = checkConfig(cfg); err != nil {
		return nil, fmt.Errorf("bad database configuration : %v", err)
	}

	if cfg["type"] == "sqlite" {
		c.Db, err = gorm.Open("sqlite3", cfg["db_path"]+"?_busy_timeout=1000")
		if err != nil {
			return nil, fmt.Errorf("failed to open %s : %s", cfg["db_path"], err)
		}
	}

	if cfg["type"] == "mysql" {
		gormArg := cfg["db_username"] + ":" + cfg["db_password"] + "@(" + cfg["db_host"] + ")/" + cfg["db_name"] + "?charset=utf8&parseTime=True&loc=Local"
		c.Db, err = gorm.Open("mysql", gormArg)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s database : %s", cfg["db_name"], err)
		}
	}

	if val, ok := cfg["debug"]; ok && val == "true" {
		log.Infof("Enabling debug for %s", cfg["type"])
		c.Db.LogMode(true)
	}

	c.flush, _ = strconv.ParseBool(cfg["flush"])
	// Migrate the schema
	c.Db.AutoMigrate(&types.EventSequence{}, &types.SignalOccurence{}, &types.BanApplication{})
	c.Db.Model(&types.SignalOccurence{}).Related(&types.EventSequence{})
	c.Db.Model(&types.SignalOccurence{}).Related(&types.BanApplication{})
	c.tx = c.Db.Begin()
	c.lastCommit = time.Now()
	ret := c.tx.Commit()

	if ret.Error != nil {
		return nil, fmt.Errorf("failed to commit records : %v", ret.Error)

	}
	c.tx = c.Db.Begin()
	if c.tx == nil {
		return nil, fmt.Errorf("failed to begin %s transac : %s", cfg["type"], err)
	}
	c.PusherTomb.Go(func() error {
		c.AutoCommit()
		return nil
	})
	return c, nil
}
