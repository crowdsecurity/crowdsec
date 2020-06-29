package database

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func (c *Context) Flush() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	ret := c.tx.Commit()

	if ret.Error != nil {
		c.tx = c.Db.Begin()
		return fmt.Errorf("failed to commit records : %v", ret.Error)
	}
	c.tx = c.Db.Begin()
	c.lastCommit = time.Now()
	//Delete the expired records
	if c.flush {
		//retx := c.Db.Where(`strftime("%s", until) < strftime("%s", "now")`).Delete(types.BanApplication{})
		retx := c.Db.Delete(types.BanApplication{}, "until < ?", c.lastCommit)
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
		case <-c.PusherTomb.Dying():
			//we need to shutdown
			log.Infof("database routine shutdown")
			if err := c.Flush(); err != nil {
				log.Errorf("error while flushing records: %s", err)
			}
			if ret := c.tx.Commit(); ret.Error != nil {
				log.Errorf("failed to commit records : %v", ret.Error)
			}
			if err := c.tx.Close(); err != nil {
				log.Errorf("error while closing tx : %s", err)
			}
			if err := c.Db.Close(); err != nil {
				log.Errorf("error while closing db : %s", err)
			}
			return
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
