package sqlite

import (
	"fmt"
	"sync/atomic"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func (c *Context) Flush() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	ret := c.tx.Commit()
	if ret.Error != nil {
		/*if the database is locked, don't overwrite the current transaction*/
		if ret.Error == sqlite3.ErrLocked {
			log.Errorf("sqlite commit : db is locked : %s", ret.Error)
			return ret.Error
		}
		/*if it's another error, create a new transaction to avoid locking ourselves in a bad state ?*/
		c.tx = c.Db.Begin()
		return fmt.Errorf("failed to commit records : %v", ret.Error)
	}
	c.tx = c.Db.Begin()
	c.lastCommit = time.Now()
	//Delete the expired records
	if c.flush {
		retx := c.Db.Where(`strftime("%s", until) < strftime("%s", "now")`).Delete(types.BanApplication{})
		if retx.RowsAffected > 0 {
			log.Infof("Flushed %d expired entries from Ban Application", retx.RowsAffected)
		}
	}
	return nil
}

func (c *Context) AutoCommit() {
	ticker := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&c.count) != 0 &&
				(atomic.LoadInt32(&c.count)%100 == 0 || time.Since(c.lastCommit) >= 500*time.Millisecond) {
				if err := c.Flush(); err != nil {
					log.Errorf("failed to flush : %s", err)
				}
			}
		}
	}
}
