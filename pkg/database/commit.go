package database

import (
	"time"

	log "github.com/sirupsen/logrus"
)

/*Flush doesn't do anything here : we are not using transactions or such, nothing to "flush" per se*/
func (c *Context) Flush() error {
	return nil
}

func (c *Context) StartAutoCommit() error {
	//TBD : we shouldn't start auto-commit if we are in cli mode ?
	c.PusherTomb.Go(func() error {
		c.autoCommit()
		return nil
	})
	return nil
}

func (c *Context) autoCommit() {
	log.Debugf("starting autocommit")
	cleanUpTicker := time.NewTicker(1 * time.Minute)
	expireTicker := time.NewTicker(1 * time.Second)
	if !c.flush {
		log.Debugf("flush is disabled")
	}
	for {
		select {
		case <-c.PusherTomb.Dying():
			//we need to shutdown
			log.Infof("database routine shutdown")
			if err := c.Flush(); err != nil {
				log.Errorf("error while flushing records: %s", err)
			}
			if err := c.Db.Close(); err != nil {
				log.Errorf("error while closing db : %s", err)
			}
			return
		case <-expireTicker.C:
			if _, err := c.DeleteExpired(); err != nil {
				log.Errorf("Error while deleting expired records: %s", err)
			}
		case <-cleanUpTicker.C:
			if _, err := c.CleanUpRecordsByCount(); err != nil {
				log.Errorf("error in max records cleanup : %s", err)
			}
			if _, err := c.CleanUpRecordsByAge(); err != nil {
				log.Errorf("error in old records cleanup : %s", err)

			}
		}
	}
}
