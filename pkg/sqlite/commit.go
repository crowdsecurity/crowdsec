package sqlite

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (c *Context) DeleteExpired() error {
	//Delete the expired records
	if c.flush {
		retx := c.Db.Where(`strftime("%s", until) < strftime("%s", "now")`).Delete(types.BanApplication{})
		if retx.RowsAffected > 0 {
			log.Infof("Flushed %d expired entries from Ban Application", retx.RowsAffected)
		}
	}
	return nil
}

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
	return nil
}

func (c *Context) CleanUpRecordsByAge() error {
	//let's fetch all expired records that are more than XX days olds
	sos := []types.BanApplication{}

	if c.maxDurationRetention == 0 {
		return nil
	}

	//look for soft-deleted events that are OLDER than maxDurationRetention
	ret := c.Db.Unscoped().Table("ban_applications").Where("deleted_at is not NULL").
		Where(fmt.Sprintf("deleted_at > date('now','-%d minutes')", int(c.maxDurationRetention.Minutes()))).
		Order("updated_at desc").Find(&sos)

	if ret.Error != nil {
		return errors.Wrap(ret.Error, "failed to get count of old records")
	}

	//no events elligible
	if len(sos) == 0 || ret.RowsAffected == 0 {
		log.Debugf("no event older than %s", c.maxDurationRetention.String())
		return nil
	}
	//let's do it in a single transaction
	delTx := c.Db.Unscoped().Begin()
	delRecords := 0

	for _, record := range sos {
		copy := record
		delTx.Unscoped().Table("signal_occurences").Where("ID = ?", copy.SignalOccurenceID).Delete(&types.SignalOccurence{})
		delTx.Unscoped().Table("event_sequences").Where("signal_occurence_id = ?", copy.SignalOccurenceID).Delete(&types.EventSequence{})
		delTx.Unscoped().Table("ban_applications").Delete(&copy)
		//we need to delete associations : event_sequences, signal_occurences
		delRecords++
	}
	ret = delTx.Unscoped().Commit()
	if ret.Error != nil {
		return errors.Wrap(ret.Error, "failed to delete records")
	}
	log.Printf("max_records_age: deleting %d events (max age:%s)", delRecords, c.maxDurationRetention)
	return nil
}

func (c *Context) CleanUpRecordsByCount() error {
	var count int

	if c.maxEventRetention <= 0 {
		return nil
	}

	ret := c.Db.Unscoped().Table("ban_applications").Order("updated_at desc").Count(&count)

	if ret.Error != nil {
		return errors.Wrap(ret.Error, "failed to get bans count")
	}
	if count < c.maxEventRetention {
		log.Debugf("%d < %d, don't cleanup", count, c.maxEventRetention)
		return nil
	}

	sos := []types.BanApplication{}
	/*get soft deleted records oldest to youngest*/
	records := c.Db.Unscoped().Table("ban_applications").Where("deleted_at is not NULL").Where(`strftime("%s", deleted_at) < strftime("%s", "now")`).Find(&sos)
	if records.Error != nil {
		return errors.Wrap(records.Error, "failed to list expired bans for flush")
	}

	//let's do it in a single transaction
	delTx := c.Db.Unscoped().Begin()
	delRecords := 0
	for _, ld := range sos {
		copy := ld
		delTx.Unscoped().Table("signal_occurences").Where("ID = ?", copy.SignalOccurenceID).Delete(&types.SignalOccurence{})
		delTx.Unscoped().Table("event_sequences").Where("signal_occurence_id = ?", copy.SignalOccurenceID).Delete(&types.EventSequence{})
		delTx.Unscoped().Table("ban_applications").Delete(&copy)
		//we need to delete associations : event_sequences, signal_occurences
		delRecords++
		//let's delete as well the associated event_sequence
		if count-delRecords <= c.maxEventRetention {
			break
		}
	}
	if len(sos) > 0 {
		//log.Printf("Deleting %d soft-deleted results out of %d total events (%d soft-deleted)", delRecords, count, len(sos))
		log.Printf("max_records: deleting %d events. (%d soft-deleted)", delRecords, len(sos))
		ret = delTx.Unscoped().Commit()
		if ret.Error != nil {
			return errors.Wrap(ret.Error, "failed to delete records")
		}
	} else {
		log.Debugf("didn't find any record to clean")
	}
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
	ticker := time.NewTicker(200 * time.Millisecond)
	cleanUpTicker := time.NewTicker(1 * time.Minute)
	expireTicker := time.NewTicker(1 * time.Second)
	if !c.flush {
		log.Debugf("flush is disabled")
	}
	for {
		select {
		case <-c.PusherTomb.Dying():
			//we need to shutdown
			log.Infof("sqlite routine shutdown")
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
		case <-expireTicker.C:
			if err := c.DeleteExpired(); err != nil {
				log.Errorf("Error while deleting expired records: %s", err)
			}
		case <-ticker.C:
			if atomic.LoadInt32(&c.count) != 0 &&
				(atomic.LoadInt32(&c.count)%100 == 0 || time.Since(c.lastCommit) >= 500*time.Millisecond) {
				if err := c.Flush(); err != nil {
					log.Errorf("failed to flush : %s", err)
				}

			}
		case <-cleanUpTicker.C:
			if err := c.CleanUpRecordsByCount(); err != nil {
				log.Errorf("error in max records cleanup : %s", err)
			}
			if err := c.CleanUpRecordsByAge(); err != nil {
				log.Errorf("error in old records cleanup : %s", err)

			}
		}
	}
}
