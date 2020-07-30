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
	lastCommit time.Time
	flush      bool
	count      int32
	lock       sync.Mutex //booboo
	PusherTomb tomb.Tomb
	//to manage auto cleanup : max number of records *or* oldest
	maxEventRetention    int
	maxDurationRetention time.Duration
}

func checkConfig(cfg map[string]string) error {
	switch dbType := cfg["type"]; dbType {
	case "sqlite":
		if val, ok := cfg["db_path"]; !ok || val == "" {
			return fmt.Errorf("please specify a 'db_path' to SQLite db in the configuration")
		}
	case "mysql":
		if val, ok := cfg["db_host"]; !ok || val == "" {
			return fmt.Errorf("please specify a 'db_host' to MySQL db in the configuration")
		}

		if val, ok := cfg["db_username"]; !ok || val == "" {
			return fmt.Errorf("please specify a 'db_username' to MySQL db in the configuration")
		}

		if val, ok := cfg["db_password"]; !ok || val == "" {
			return fmt.Errorf("please specify a 'db_password' to MySQL db in the configuration")
		}

		if val, ok := cfg["db_name"]; !ok || val == "" {
			return fmt.Errorf("please specify a 'db_name' to MySQL db in the configuration")
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
		c.Db, err = gorm.Open("sqlite3", cfg["db_path"]+"?_busy_timeout=10000")
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

	if v, ok := cfg["max_records"]; ok {
		c.maxEventRetention, err = strconv.Atoi(v)
		if err != nil {
			log.Errorf("Ignoring invalid max_records '%s' : %s", v, err)
		}
	}
	if v, ok := cfg["max_records_age"]; ok {
		c.maxDurationRetention, err = time.ParseDuration(v)
		if err != nil {
			log.Errorf("Ignoring invalid duration '%s' : %s", v, err)
		}
	}

	if val, ok := cfg["debug"]; ok && val == "true" {
		log.Infof("Enabling debug for %s", cfg["type"])
		c.Db.LogMode(true)
	}

	c.flush, err = strconv.ParseBool(cfg["flush"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse 'flush' value %s : %s", cfg["flush"], err)
	}
	// Migrate the schema
	c.Db.AutoMigrate(&types.EventSequence{}, &types.SignalOccurence{}, &types.BanApplication{})
	c.Db.Model(&types.SignalOccurence{}).Related(&types.EventSequence{})
	c.Db.Model(&types.SignalOccurence{}).Related(&types.BanApplication{})

	c.lastCommit = time.Now()
	return c, nil
}
