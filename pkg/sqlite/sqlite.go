package sqlite

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/tomb.v2"
)

type Context struct {
	Db         *gorm.DB //Pointer to sqlite db
	tx         *gorm.DB //Pointer to current transaction (flushed on a regular basis)
	lastCommit time.Time
	flush      bool
	count      int32
	lock       sync.Mutex //booboo
	PusherTomb tomb.Tomb
}

func NewSQLite(cfg map[string]string) (*Context, error) {
	var err error
	c := &Context{}

	if _, ok := cfg["db_path"]; !ok {
		return nil, fmt.Errorf("please specify a 'db_path' to SQLite db in the configuration")
	}

	if cfg["db_path"] == "" {
		return nil, fmt.Errorf("please specify a 'db_path' to SQLite db in the configuration")
	}

	c.Db, err = gorm.Open("sqlite3", cfg["db_path"]+"?_busy_timeout=1000")
	if err != nil {
		return nil, fmt.Errorf("failed to open %s : %s", cfg["db_path"], err)
	}

	if val, ok := cfg["debug"]; ok && val == "true" {
		log.Infof("Enabling debug for sqlite")
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
		return nil, fmt.Errorf("failed to begin sqlite transac : %s", err)
	}
	c.PusherTomb.Go(func() error {
		c.AutoCommit()
		return nil
	})
	return c, nil
}
