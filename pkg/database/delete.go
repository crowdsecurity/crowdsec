package database

import (
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

/*try to delete entries with matching fields */
func (c *Context) DeleteBan(target string) (int, error) {

	if target != "" {
		ret := c.Db.Delete(types.BanApplication{}, "ip_text = ?", target)
		if ret.Error != nil {
			log.Errorf("Failed to delete record with BanTarget %s : %v", target, ret.Error)
			return 0, ret.Error
		}
		return int(ret.RowsAffected), nil
	}
	return 0, fmt.Errorf("no target provided")
}

func (c *Context) DeleteAll() error {
	allBa := types.BanApplication{}
	records := c.Db.Unscoped().Delete(&allBa)
	if records.Error != nil {
		return records.Error
	}
	return nil
}

func (c *Context) DeleteExpired() (int, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	//Delete the expired records
	now := time.Now()
	count := 0
	if c.flush {
		retx := c.Db.Delete(types.BanApplication{}, "until < ?", now)
		if retx.Error != nil {
			return 0, retx.Error
		}
		if retx.RowsAffected > 0 {
			log.Infof("Flushed %d expired entries from Ban Application", retx.RowsAffected)
			count = int(retx.RowsAffected)
		}
	}
	return count, nil
}

func (c *Context) CleanUpRecordsByAge() (int, error) {
	//let's fetch all expired records that are more than XX days olds
	sos := []types.BanApplication{}

	if c.maxDurationRetention == 0 {
		return 0, nil
	}

	//look for soft-deleted events that are OLDER than maxDurationRetention
	ret := c.Db.Unscoped().Table("ban_applications").Where("deleted_at is not NULL").
		Where("until < ?", time.Now().Add(-c.maxDurationRetention)).
		Order("updated_at desc").Find(&sos)

	if ret.Error != nil {
		return 0, errors.Wrap(ret.Error, "failed to get count of old records")
	}

	//no events elligible
	if len(sos) == 0 || ret.RowsAffected == 0 {
		log.Debugf("no event older than %s", c.maxDurationRetention.String())
		return 0, nil
	}

	/*This is clearly suboptimal, and 'left join' and stuff gives way better results, but doesn't seem to behave equally on sqlite and mysql*/
	delRecords := 0
	for _, record := range sos {
		copy := record
		if ret := c.Db.Unscoped().Table("signal_occurences").Where("ID = ?", copy.SignalOccurenceID).Delete(&types.SignalOccurence{}); ret.Error != nil {
			return 0, errors.Wrap(ret.Error, "failed to clean signal_occurences")
		}
		if ret := c.Db.Unscoped().Table("event_sequences").Where("signal_occurence_id = ?", copy.SignalOccurenceID).Delete(&types.EventSequence{}); ret.Error != nil {
			return 0, errors.Wrap(ret.Error, "failed to clean event_sequences")
		}
		if ret := c.Db.Unscoped().Table("ban_applications").Delete(&copy); ret.Error != nil {
			return 0, errors.Wrap(ret.Error, "failed to clean ban_applications")
		}
		delRecords++
	}
	log.Printf("max_records_age: deleting %d events (max age:%s)", delRecords, c.maxDurationRetention)
	return delRecords, nil
}

func (c *Context) CleanUpRecordsByCount() (int, error) {
	var count int

	if c.maxEventRetention <= 0 {
		return 0, nil
	}

	ret := c.Db.Unscoped().Table("ban_applications").Count(&count)

	if ret.Error != nil {
		return 0, errors.Wrap(ret.Error, "failed to get bans count")
	}
	if count < c.maxEventRetention {
		log.Debugf("%d < %d, don't cleanup", count, c.maxEventRetention)
		return 0, nil
	}

	sos := []types.BanApplication{}
	now := time.Now()
	/*get soft deleted records oldest to youngest*/
	//records := c.Db.Unscoped().Table("ban_applications").Where("deleted_at is not NULL").Where(`strftime("%s", deleted_at) < strftime("%s", "now")`).Find(&sos)
	records := c.Db.Unscoped().Table("ban_applications").Where("deleted_at is not NULL").Where("deleted_at < ?", now).Find(&sos)
	if records.Error != nil {
		return 0, errors.Wrap(records.Error, "failed to list expired bans for flush")
	}

	//let's do it in a single transaction
	delRecords := 0
	for _, ld := range sos {
		copy := ld
		if ret := c.Db.Unscoped().Table("signal_occurences").Where("ID = ?", copy.SignalOccurenceID).Delete(&types.SignalOccurence{}); ret.Error != nil {
			return 0, errors.Wrap(ret.Error, "failed to clean signal_occurences")
		}
		if ret := c.Db.Unscoped().Table("event_sequences").Where("signal_occurence_id = ?", copy.SignalOccurenceID).Delete(&types.EventSequence{}); ret.Error != nil {
			return 0, errors.Wrap(ret.Error, "failed to clean event_sequences")
		}
		if ret := c.Db.Unscoped().Table("ban_applications").Delete(&copy); ret.Error != nil {
			return 0, errors.Wrap(ret.Error, "failed to clean ban_applications")
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
	return delRecords, nil
}
