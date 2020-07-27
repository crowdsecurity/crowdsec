package database

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (c *Context) DeleteExpired() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	//Delete the expired records
	now := time.Now()
	if c.flush {
		retx := c.Db.Delete(types.BanApplication{}, "until < ?", now)
		if retx.RowsAffected > 0 {
			log.Infof("Flushed %d expired entries from Ban Application", retx.RowsAffected)
		}
	}
	return nil
}

/*Flush doesn't do anything here : we are not using transactions or such, nothing to "flush" per se*/
func (c *Context) Flush() error {
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
		Where("deleted_at < ?", time.Now().Add(-c.maxDurationRetention)).
		Order("updated_at desc").Find(&sos)

	if ret.Error != nil {
		return errors.Wrap(ret.Error, "failed to get count of old records")
	}

	//no events elligible
	if len(sos) == 0 || ret.RowsAffected == 0 {
		log.Debugf("no event older than %s", c.maxDurationRetention.String())
		return nil
	}

	delRecords := 0
	for _, record := range sos {
		copy := record
		if ret := c.Db.Unscoped().Table("signal_occurences").Where("ID = ?", copy.SignalOccurenceID).Delete(&types.SignalOccurence{}); ret.Error != nil {
			return errors.Wrap(ret.Error, "failed to clean signal_occurences")
		}
		if ret := c.Db.Unscoped().Table("event_sequences").Where("signal_occurence_id = ?", copy.SignalOccurenceID).Delete(&types.EventSequence{}); ret.Error != nil {
			return errors.Wrap(ret.Error, "failed to clean event_sequences")
		}
		if ret := c.Db.Unscoped().Table("ban_applications").Delete(&copy); ret.Error != nil {
			return errors.Wrap(ret.Error, "failed to clean ban_applications")
		}
		delRecords++
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
	now := time.Now()
	/*get soft deleted records oldest to youngest*/
	//records := c.Db.Unscoped().Table("ban_applications").Where("deleted_at is not NULL").Where(`strftime("%s", deleted_at) < strftime("%s", "now")`).Find(&sos)
	records := c.Db.Unscoped().Table("ban_applications").Where("deleted_at is not NULL").Where("deleted_at < ?", now).Find(&sos)
	if records.Error != nil {
		return errors.Wrap(records.Error, "failed to list expired bans for flush")
	}

	//let's do it in a single transaction
	delRecords := 0
	for _, ld := range sos {
		copy := ld
		if ret := c.Db.Unscoped().Table("signal_occurences").Where("ID = ?", copy.SignalOccurenceID).Delete(&types.SignalOccurence{}); ret.Error != nil {
			return errors.Wrap(ret.Error, "failed to clean signal_occurences")
		}
		if ret := c.Db.Unscoped().Table("event_sequences").Where("signal_occurence_id = ?", copy.SignalOccurenceID).Delete(&types.EventSequence{}); ret.Error != nil {
			return errors.Wrap(ret.Error, "failed to clean event_sequences")
		}
		if ret := c.Db.Unscoped().Table("ban_applications").Delete(&copy); ret.Error != nil {
			return errors.Wrap(ret.Error, "failed to clean ban_applications")
		}
		//we need to delete associations : event_sequences, signal_occurences
		delRecords++
		//let's delete as well the associated event_sequence
		if count-delRecords <= c.maxEventRetention {
			break
		}
	}
	if len(sos) > 0 {
		log.Printf("max_records: deleting %d events. (%d soft-deleted)", delRecords, len(sos))
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
			if err := c.DeleteExpired(); err != nil {
				log.Errorf("Error while deleting expired records: %s", err)
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
